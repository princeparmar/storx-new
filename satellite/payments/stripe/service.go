// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shopspring/decimal"
	"github.com/spacemonkeygo/monkit/v3"
	"github.com/stripe/stripe-go/v72"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/currency"
	"storj.io/common/sync2"
	"storj.io/common/uuid"
	"storj.io/storj/satellite/accounting"
	"storj.io/storj/satellite/analytics"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/payments"
	"storj.io/storj/satellite/payments/billing"
	"storj.io/storj/satellite/payments/storjscan"
)

var (
	// Error defines stripecoinpayments service error.
	Error = errs.Class("stripecoinpayments service")

	mon = monkit.Package()
)

// hoursPerMonth is the number of months in a billing month. For the purpose of billing, the billing month is always 30 days.
const hoursPerMonth = 24 * 30

// Config stores needed information for payment service initialization.
type Config struct {
	StripeSecretKey        string `help:"stripe API secret key" default:""`
	StripePublicKey        string `help:"stripe API public key" default:""`
	StripeFreeTierCouponID string `help:"stripe free tier coupon ID" default:""`
	AutoAdvance            bool   `help:"toggle autoadvance feature for invoice creation" default:"false"`
	ListingLimit           int    `help:"sets the maximum amount of items before we start paging on requests" default:"100" hidden:"true"`
	SkipEmptyInvoices      bool   `help:"if set, skips the creation of empty invoices for customers with zero usage for the billing period" default:"true"`
	MaxParallelCalls       int    `help:"the maximum number of concurrent Stripe API calls in invoicing methods" default:"10"`
	RemoveExpiredCredit    bool   `help:"whether to remove expired package credit or not" default:"true"`
	Retries                RetryConfig
}

// Service is an implementation for payment service via Stripe and Coinpayments.
//
// architecture: Service
type Service struct {
	log *zap.Logger

	db        DB
	walletsDB storjscan.WalletsDB
	billingDB billing.TransactionsDB

	projectsDB   console.Projects
	usersDB      console.Users
	usageDB      accounting.ProjectAccounting
	stripeClient Client

	analytics *analytics.Service

	usagePrices         payments.ProjectUsagePriceModel
	usagePriceOverrides map[string]payments.ProjectUsagePriceModel
	packagePlans        map[string]payments.PackagePlan
	partnerNames        []string
	// BonusRate amount of percents
	BonusRate int64
	// Coupon Values
	StripeFreeTierCouponID string

	// Stripe Extended Features
	AutoAdvance bool

	listingLimit        int
	skipEmptyInvoices   bool
	maxParallelCalls    int
	removeExpiredCredit bool
	nowFn               func() time.Time
}

// NewService creates a Service instance.
func NewService(log *zap.Logger, stripeClient Client, config Config, db DB, walletsDB storjscan.WalletsDB, billingDB billing.TransactionsDB, projectsDB console.Projects, usersDB console.Users, usageDB accounting.ProjectAccounting, usagePrices payments.ProjectUsagePriceModel, usagePriceOverrides map[string]payments.ProjectUsagePriceModel, packagePlans map[string]payments.PackagePlan, bonusRate int64, analyticsService *analytics.Service) (*Service, error) {
	var partners []string
	for partner := range usagePriceOverrides {
		partners = append(partners, partner)
	}

	return &Service{
		log:                    log,
		db:                     db,
		walletsDB:              walletsDB,
		billingDB:              billingDB,
		projectsDB:             projectsDB,
		usersDB:                usersDB,
		usageDB:                usageDB,
		stripeClient:           stripeClient,
		analytics:              analyticsService,
		usagePrices:            usagePrices,
		usagePriceOverrides:    usagePriceOverrides,
		packagePlans:           packagePlans,
		partnerNames:           partners,
		BonusRate:              bonusRate,
		StripeFreeTierCouponID: config.StripeFreeTierCouponID,
		AutoAdvance:            config.AutoAdvance,
		listingLimit:           config.ListingLimit,
		skipEmptyInvoices:      config.SkipEmptyInvoices,
		maxParallelCalls:       config.MaxParallelCalls,
		removeExpiredCredit:    config.RemoveExpiredCredit,
		nowFn:                  time.Now,
	}, nil
}

// Accounts exposes all needed functionality to manage payment accounts.
func (service *Service) Accounts() payments.Accounts {
	return &accounts{service: service}
}

// PrepareInvoiceProjectRecords iterates through all projects and creates invoice records if none exist.
func (service *Service) PrepareInvoiceProjectRecords(ctx context.Context, period time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	now := service.nowFn().UTC()
	utc := period.UTC()

	start := time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(utc.Year(), utc.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	if end.After(now) {
		return Error.New("allowed for past periods only")
	}

	var numberOfCustomers, numberOfRecords int
	customersPage := CustomersPage{
		Next: true,
	}

	for customersPage.Next {
		if err = ctx.Err(); err != nil {
			return Error.Wrap(err)
		}

		customersPage, err = service.db.Customers().List(ctx, customersPage.Cursor, service.listingLimit, end)
		if err != nil {
			return Error.Wrap(err)
		}
		numberOfCustomers += len(customersPage.Customers)

		records, err := service.processCustomers(ctx, customersPage.Customers, start, end)
		if err != nil {
			return Error.Wrap(err)
		}
		numberOfRecords += records
	}

	service.log.Info("Number of processed entries.", zap.Int("Customers", numberOfCustomers), zap.Int("Projects", numberOfRecords))
	return nil
}

func (service *Service) processCustomers(ctx context.Context, customers []Customer, start, end time.Time) (int, error) {
	var allRecords []CreateProjectRecord
	for _, customer := range customers {
		projects, err := service.projectsDB.GetOwn(ctx, customer.UserID)
		if err != nil {
			return 0, err
		}

		records, err := service.createProjectRecords(ctx, customer.ID, projects, start, end)
		if err != nil {
			return 0, err
		}

		allRecords = append(allRecords, records...)
	}

	return len(allRecords), service.db.ProjectRecords().Create(ctx, allRecords, start, end)
}

// createProjectRecords creates invoice project record if none exists.
func (service *Service) createProjectRecords(ctx context.Context, customerID string, projects []console.Project, start, end time.Time) (_ []CreateProjectRecord, err error) {
	defer mon.Task()(&ctx)(&err)

	var records []CreateProjectRecord
	for _, project := range projects {
		if err = ctx.Err(); err != nil {
			return nil, err
		}

		if err = service.db.ProjectRecords().Check(ctx, project.ID, start, end); err != nil {
			if errors.Is(err, ErrProjectRecordExists) {
				service.log.Warn("Record for this project already exists.", zap.String("Customer ID", customerID), zap.String("Project ID", project.ID.String()))
				continue
			}

			return nil, err
		}

		usage, err := service.usageDB.GetProjectTotal(ctx, project.ID, start, end)
		if err != nil {
			return nil, err
		}

		// TODO: account for usage data.
		records = append(records,
			CreateProjectRecord{
				ProjectID: project.ID,
				Storage:   usage.Storage,
				Egress:    usage.Egress,
				Segments:  usage.SegmentCount,
			},
		)
	}

	return records, nil
}

// InvoiceApplyProjectRecords iterates through unapplied invoice project records and creates invoice line items
// for stripe customer.
func (service *Service) InvoiceApplyProjectRecords(ctx context.Context, period time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	now := service.nowFn().UTC()
	utc := period.UTC()

	start := time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(utc.Year(), utc.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	if end.After(now) {
		return Error.New("allowed for past periods only")
	}

	var totalRecords int
	var totalSkipped int

	for {
		if err = ctx.Err(); err != nil {
			return Error.Wrap(err)
		}

		// we are always starting from offset 0 because applyProjectRecords is changing project record state to applied
		recordsPage, err := service.db.ProjectRecords().ListUnapplied(ctx, uuid.UUID{}, service.listingLimit, start, end)
		if err != nil {
			return Error.Wrap(err)
		}
		totalRecords += len(recordsPage.Records)

		skipped, err := service.applyProjectRecords(ctx, recordsPage.Records)
		if err != nil {
			return Error.Wrap(err)
		}
		totalSkipped += skipped

		if !recordsPage.Next {
			break
		}
	}

	service.log.Info("Processed project records.",
		zap.Int("Total", totalRecords),
		zap.Int("Skipped", totalSkipped))
	return nil
}

// InvoiceApplyTokenBalance iterates through customer storjscan wallets and creates invoice credit notes
// for stripe customers with invoices on or after the given date.
func (service *Service) InvoiceApplyTokenBalance(ctx context.Context, createdOnAfter time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	// get all wallet entries
	wallets, err := service.walletsDB.GetAll(ctx)
	if err != nil {
		return Error.New("unable to get users in the wallets table")
	}

	var errGrp errs.Group

	for _, wallet := range wallets {
		// get the stripe customer invoice balance
		customerID, err := service.db.Customers().GetCustomerID(ctx, wallet.UserID)
		if err != nil {
			errGrp.Add(Error.New("unable to get stripe customer ID for user ID %s", wallet.UserID.String()))
			continue
		}
		customerInvoices, err := service.getInvoices(ctx, customerID, createdOnAfter)
		if err != nil {
			errGrp.Add(Error.New("unable to get invoice balance for stripe customer ID %s", customerID))
			continue
		}
		err = service.payInvoicesWithTokenBalance(ctx, customerID, wallet, customerInvoices)
		if err != nil {
			errGrp.Add(Error.New("unable to pay invoices for stripe customer ID %s", customerID))
			continue
		}
	}
	return errGrp.Err()
}

// InvoiceApplyCustomerTokenBalance creates invoice credit notes for the customers token payments to open invoices.
func (service *Service) InvoiceApplyCustomerTokenBalance(ctx context.Context, customerID string) (err error) {
	defer mon.Task()(&ctx)(&err)

	userID, err := service.db.Customers().GetUserID(ctx, customerID)
	if err != nil {
		return Error.New("unable to get user ID for stripe customer ID %s", customerID)
	}

	customerInvoices, err := service.getInvoices(ctx, customerID, time.Unix(0, 0))
	if err != nil {
		return Error.New("error getting invoices for stripe customer %s", customerID)
	}

	return service.PayInvoicesWithTokenBalance(ctx, userID, customerID, customerInvoices)
}

// getInvoices returns the stripe customer's open finalized invoices created on or after the given date.
func (service *Service) getInvoices(ctx context.Context, cusID string, createdOnAfter time.Time) (_ []stripe.Invoice, err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.InvoiceListParams{
		ListParams: stripe.ListParams{Context: ctx},
		Customer:   stripe.String(cusID),
		Status:     stripe.String(string(stripe.InvoiceStatusOpen)),
	}
	params.Filters.AddFilter("created", "gte", strconv.FormatInt(createdOnAfter.Unix(), 10))
	invoicesIterator := service.stripeClient.Invoices().List(params)
	var stripeInvoices []stripe.Invoice
	for invoicesIterator.Next() {
		stripeInvoice := invoicesIterator.Invoice()
		if stripeInvoice != nil {
			stripeInvoices = append(stripeInvoices, *stripeInvoice)
		}
	}
	if err = invoicesIterator.Err(); err != nil {
		return stripeInvoices, Error.Wrap(err)
	}
	return stripeInvoices, nil
}

// addCreditNoteToInvoice creates a credit note for the user token payment.
func (service *Service) addCreditNoteToInvoice(ctx context.Context, invoiceID, cusID, wallet string, amount, txID int64) (_ string, err error) {
	defer mon.Task()(&ctx)(&err)

	var lineParams []*stripe.CreditNoteLineParams

	lineParam := stripe.CreditNoteLineParams{
		Description: stripe.String("Storjscan Token payment"),
		Type:        stripe.String("custom_line_item"),
		UnitAmount:  stripe.Int64(amount),
		Quantity:    stripe.Int64(1),
	}

	lineParams = append(lineParams, &lineParam)

	params := &stripe.CreditNoteParams{
		Params:  stripe.Params{Context: ctx},
		Invoice: stripe.String(invoiceID),
		Lines:   lineParams,
		Memo:    stripe.String("Storjscan Token Payment - Wallet: " + wallet),
	}
	params.AddMetadata("txID", strconv.FormatInt(txID, 10))
	params.AddMetadata("wallet address", wallet)
	creditNote, err := service.stripeClient.CreditNotes().New(params)
	if err != nil {
		service.log.Warn("unable to add credit note for stripe customer", zap.String("Customer ID", cusID))
		return "", Error.Wrap(err)
	}
	return creditNote.ID, nil
}

// createTokenPaymentBillingTransaction creates a billing DB entry for the user token payment.
func (service *Service) createTokenPaymentBillingTransaction(ctx context.Context, userID uuid.UUID, invoiceID, wallet string, amount int64) (_ int64, err error) {
	defer mon.Task()(&ctx)(&err)

	metadata, err := json.Marshal(map[string]interface{}{
		"InvoiceID": invoiceID,
		"Wallet":    wallet,
	})

	transaction := billing.Transaction{
		UserID:      userID,
		Amount:      currency.AmountFromBaseUnits(amount, currency.USDollars),
		Description: "Paid Stripe Invoice",
		Source:      billing.StripeSource,
		Status:      billing.TransactionStatusPending,
		Type:        billing.TransactionTypeDebit,
		Metadata:    metadata,
		Timestamp:   time.Now(),
	}
	txIDs, err := service.billingDB.Insert(ctx, transaction)
	if err != nil {
		service.log.Warn("unable to add transaction to billing DB for user", zap.String("User ID", userID.String()))
		return 0, Error.Wrap(err)
	}
	return txIDs[0], nil
}

// boris
func (service *Service) CreateTokenPaymentBillingTransaction(ctx context.Context, user *console.User, amountTemp string) (err error) {
	defer mon.Task()(&ctx)(&err)

	amount, err := strconv.ParseFloat(amountTemp, 64)

	transaction := billing.Transactions{
		UserID:      user.ID,
		Amount:      amount,
		Description: "Paid Stripe Invoice",
		Source:      billing.StripeSource,
		Status:      billing.TransactionStatusCompleted,
		Type:        billing.TransactionTypeDebit,
		Timestamp:   time.Now(),
		CreatedAt:   time.Now(),
	}

	err = service.billingDB.Inserts(ctx, transaction)

	if err != nil {
		service.log.Warn("unable to add transaction to billing DB for user", zap.String("User ID", user.ID.String()))
		return Error.Wrap(err)
	}
	return nil
}

// boris
func (service *Service) GetBillingHistory(ctx context.Context, userID uuid.UUID) ([]billing.Transactions, error) {
	billingRows, err := service.billingDB.Lists(ctx, userID)
	return billingRows, err

}

// applyProjectRecords applies invoice intents as invoice line items to stripe customer.
func (service *Service) applyProjectRecords(ctx context.Context, records []ProjectRecord) (skipCount int, err error) {
	defer mon.Task()(&ctx)(&err)

	var mu sync.Mutex
	var errGrp errs.Group
	limiter := sync2.NewLimiter(service.maxParallelCalls)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		limiter.Wait()
	}()

	for _, record := range records {
		if err = ctx.Err(); err != nil {
			return 0, errs.Wrap(err)
		}

		proj, err := service.projectsDB.Get(ctx, record.ProjectID)
		if err != nil {
			// This should never happen, but be sure to log info to further troubleshoot before exiting.
			service.log.Error("project ID for corresponding project record not found", zap.Stringer("Record ID", record.ID), zap.Stringer("Project ID", record.ProjectID))
			return 0, errs.Wrap(err)
		}

		cusID, err := service.db.Customers().GetCustomerID(ctx, proj.OwnerID)
		if err != nil {
			if errors.Is(err, ErrNoCustomer) {
				service.log.Warn("Stripe customer does not exist for project owner.", zap.Stringer("Owner ID", proj.OwnerID), zap.Stringer("Project ID", proj.ID))
				continue
			}

			return 0, errs.Wrap(err)
		}

		record := record
		limiter.Go(ctx, func() {
			skipped, err := service.createInvoiceItems(ctx, cusID, proj.Name, record)
			if err != nil {
				mu.Lock()
				errGrp.Add(errs.Wrap(err))
				mu.Unlock()
				return
			}
			if skipped {
				mu.Lock()
				skipCount++
				mu.Unlock()
			}
		})
	}

	limiter.Wait()

	return skipCount, errGrp.Err()
}

// createInvoiceItems creates invoice line items for stripe customer.
func (service *Service) createInvoiceItems(ctx context.Context, cusID, projName string, record ProjectRecord) (skipped bool, err error) {
	defer mon.Task()(&ctx)(&err)

	if err = service.db.ProjectRecords().Consume(ctx, record.ID); err != nil {
		return false, err
	}

	if service.skipEmptyInvoices && doesProjectRecordHaveNoUsage(record) {
		return true, nil
	}

	usages, err := service.usageDB.GetProjectTotalByPartner(ctx, record.ProjectID, service.partnerNames, record.PeriodStart, record.PeriodEnd)
	if err != nil {
		return false, err
	}

	items := service.InvoiceItemsFromProjectUsage(projName, usages)
	for _, item := range items {
		item.Params = stripe.Params{Context: ctx}
		item.Currency = stripe.String(string(stripe.CurrencyUSD))
		item.Customer = stripe.String(cusID)
		item.AddMetadata("projectID", record.ProjectID.String())

		_, err = service.stripeClient.InvoiceItems().New(item)
		if err != nil {
			return false, err
		}
	}

	return false, nil
}

// InvoiceItemsFromProjectUsage calculates Stripe invoice item from project usage.
func (service *Service) InvoiceItemsFromProjectUsage(projName string, partnerUsages map[string]accounting.ProjectUsage) (result []*stripe.InvoiceItemParams) {
	var partners []string
	if len(partnerUsages) == 0 {
		partners = []string{""}
		partnerUsages = map[string]accounting.ProjectUsage{"": {}}
	} else {
		for partner := range partnerUsages {
			partners = append(partners, partner)
		}
		sort.Strings(partners)
	}

	for _, partner := range partners {
		priceModel := service.Accounts().GetProjectUsagePriceModel(partner)

		usage := partnerUsages[partner]
		usage.Egress = applyEgressDiscount(usage, priceModel)

		prefix := "Project " + projName
		if partner != "" {
			prefix += " (" + partner + ")"
		}

		projectItem := &stripe.InvoiceItemParams{}
		projectItem.Description = stripe.String(prefix + " - Segment Storage (MB-Month)")
		projectItem.Quantity = stripe.Int64(storageMBMonthDecimal(usage.Storage).IntPart())
		storagePrice, _ := priceModel.StorageMBMonthCents.Float64()
		projectItem.UnitAmountDecimal = stripe.Float64(storagePrice)
		result = append(result, projectItem)

		projectItem = &stripe.InvoiceItemParams{}
		projectItem.Description = stripe.String(prefix + " - Egress Bandwidth (MB)")
		projectItem.Quantity = stripe.Int64(egressMBDecimal(usage.Egress).IntPart())
		egressPrice, _ := priceModel.EgressMBCents.Float64()
		projectItem.UnitAmountDecimal = stripe.Float64(egressPrice)
		result = append(result, projectItem)

		projectItem = &stripe.InvoiceItemParams{}
		projectItem.Description = stripe.String(prefix + " - Segment Fee (Segment-Month)")
		projectItem.Quantity = stripe.Int64(segmentMonthDecimal(usage.SegmentCount).IntPart())
		segmentPrice, _ := priceModel.SegmentMonthCents.Float64()
		projectItem.UnitAmountDecimal = stripe.Float64(segmentPrice)
		result = append(result, projectItem)
	}

	service.log.Info("invoice items", zap.Any("result", result))

	return result
}

// RemoveExpiredPackageCredit removes a user's package plan credit, or sends an analytics event, if it has expired.
// If the user has never received credit from anything other than the package, and it is expired, the remaining package
// credit is removed. If the user has received credit from another source, we send an analytics event instead of removing
// the remaining credit so someone can remove it manually. `sentEvent` indicates whether this analytics event was sent.
func (service *Service) RemoveExpiredPackageCredit(ctx context.Context, customer Customer) (sentEvent bool, err error) {
	defer mon.Task()(&ctx)(&err)

	// TODO: store the package expiration somewhere
	if customer.PackagePlan == nil || customer.PackagePurchasedAt == nil ||
		customer.PackagePurchasedAt.After(service.nowFn().AddDate(-1, -1, 0)) {
		return false, nil
	}
	list := service.stripeClient.CustomerBalanceTransactions().List(&stripe.CustomerBalanceTransactionListParams{
		Customer: stripe.String(customer.ID),
	})

	var balance int64
	var gotBalance, foundOtherCredit bool
	var tx *stripe.CustomerBalanceTransaction

	for list.Next() {
		tx = list.CustomerBalanceTransaction()
		if !gotBalance {
			// Stripe returns list ordered by most recent, so ending balance of the first item is current balance.
			balance = tx.EndingBalance
			gotBalance = true
			// if user doesn't have credit, we're done.
			if balance >= 0 {
				break
			}
		}

		// negative amount means credit
		if tx.Amount < 0 {
			if tx.Description != *customer.PackagePlan {
				foundOtherCredit = true
			}
		}
	}

	// send analytics event to notify someone to handle removing credit if credit other than package exists.
	if foundOtherCredit {
		if service.analytics != nil {
			service.analytics.TrackExpiredCreditNeedsRemoval(customer.UserID, customer.ID, *customer.PackagePlan)
		}
		return true, nil
	}

	// If no other credit found, we can set the balance to zero.
	if balance < 0 {
		_, err = service.stripeClient.CustomerBalanceTransactions().New(&stripe.CustomerBalanceTransactionParams{
			Customer:    stripe.String(customer.ID),
			Amount:      stripe.Int64(-balance),
			Currency:    stripe.String(string(stripe.CurrencyUSD)),
			Description: stripe.String(fmt.Sprintf("%s expired", *customer.PackagePlan)),
		})
		if err != nil {
			return false, Error.Wrap(err)
		}
		if service.analytics != nil {
			service.analytics.TrackExpiredCreditRemoved(customer.UserID, customer.ID, *customer.PackagePlan)
		}
	}

	err = service.Accounts().UpdatePackage(ctx, customer.UserID, nil, nil)

	return false, Error.Wrap(err)
}

// ApplyFreeTierCoupons iterates through all customers in Stripe. For each customer,
// if that customer does not currently have a Stripe coupon, the free tier Stripe coupon
// is applied.
func (service *Service) ApplyFreeTierCoupons(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	customers := service.db.Customers()

	limiter := sync2.NewLimiter(service.maxParallelCalls)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		limiter.Wait()
	}()

	var mu sync.Mutex
	var appliedCoupons int
	failedUsers := []string{}
	morePages := true
	var nextCursor uuid.UUID
	listingLimit := 100
	end := time.Now()
	for morePages {
		customersPage, err := customers.List(ctx, nextCursor, listingLimit, end)
		if err != nil {
			return err
		}
		morePages = customersPage.Next
		nextCursor = customersPage.Cursor

		for _, c := range customersPage.Customers {
			cusID := c.ID
			limiter.Go(ctx, func() {
				applied, err := service.applyFreeTierCoupon(ctx, cusID)
				if err != nil {
					mu.Lock()
					failedUsers = append(failedUsers, cusID)
					mu.Unlock()
					return
				}
				if applied {
					mu.Lock()
					appliedCoupons++
					mu.Unlock()
				}
			})
		}
	}

	limiter.Wait()

	if len(failedUsers) > 0 {
		service.log.Warn("Failed to get or apply free tier coupon to some customers:", zap.String("idlist", strings.Join(failedUsers, ", ")))
	}
	service.log.Info("Finished", zap.Int("number of coupons applied", appliedCoupons))

	return nil
}

// applyFreeTierCoupon applies the free tier Stripe coupon to a customer if it doesn't already have a coupon.
func (service *Service) applyFreeTierCoupon(ctx context.Context, cusID string) (applied bool, err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.CustomerParams{Params: stripe.Params{Context: ctx}}
	stripeCust, err := service.stripeClient.Customers().Get(cusID, params)
	if err != nil {
		service.log.Error("Failed to get customer", zap.Error(err))
		return false, err
	}

	// if customer has a coupon, don't apply the free tier coupon
	if stripeCust.Discount != nil && stripeCust.Discount.Coupon != nil {
		return false, nil
	}

	params = &stripe.CustomerParams{
		Params: stripe.Params{Context: ctx},
		Coupon: stripe.String(service.StripeFreeTierCouponID),
	}
	_, err = service.stripeClient.Customers().Update(cusID, params)
	if err != nil {
		service.log.Error("Failed to update customer with free tier coupon", zap.Error(err))
		return false, err
	}

	return true, nil
}

// CreateInvoices lists through all customers, removes expired credit if applicable, and creates invoices.
func (service *Service) CreateInvoices(ctx context.Context, period time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	now := service.nowFn().UTC()
	utc := period.UTC()

	start := time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(utc.Year(), utc.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	if end.After(now) {
		return Error.New("allowed for past periods only")
	}

	var nextCursor uuid.UUID
	var totalDraft, totalScheduled int
	for {
		cusPage, err := service.db.Customers().List(ctx, nextCursor, service.listingLimit, end)
		if err != nil {
			return Error.Wrap(err)
		}

		if service.removeExpiredCredit {
			for _, c := range cusPage.Customers {
				if c.PackagePlan != nil {
					if _, err := service.RemoveExpiredPackageCredit(ctx, c); err != nil {
						return Error.Wrap(err)
					}
				}
			}
		}

		scheduled, draft, err := service.createInvoices(ctx, cusPage.Customers, start)
		if err != nil {
			return Error.Wrap(err)
		}
		totalScheduled += scheduled
		totalDraft += draft

		if !cusPage.Next {
			break
		}
		nextCursor = cusPage.Cursor
	}

	service.log.Info("Number of created invoices", zap.Int("Draft", totalDraft), zap.Int("Scheduled", totalScheduled))
	return nil
}

// createInvoice creates invoice for Stripe customer.
func (service *Service) createInvoice(ctx context.Context, cusID string, period time.Time) (stripeInvoice *stripe.Invoice, err error) {
	defer mon.Task()(&ctx)(&err)

	description := fmt.Sprintf("Storj DCS Cloud Storage for %s %d", period.Month(), period.Year())
	stripeInvoice, err = service.stripeClient.Invoices().New(
		&stripe.InvoiceParams{
			Params:      stripe.Params{Context: ctx},
			Customer:    stripe.String(cusID),
			AutoAdvance: stripe.Bool(service.AutoAdvance),
			Description: stripe.String(description),
		},
	)

	if err != nil {
		var stripErr *stripe.Error
		if errors.As(err, &stripErr) {
			if stripErr.Code == stripe.ErrorCodeInvoiceNoCustomerLineItems {
				return stripeInvoice, nil
			}
		}
		return nil, err
	}

	// auto advance the invoice if nothing is due from the customer
	if !stripeInvoice.AutoAdvance && stripeInvoice.AmountDue == 0 {
		params := &stripe.InvoiceParams{
			Params:      stripe.Params{Context: ctx},
			AutoAdvance: stripe.Bool(true),
		}
		stripeInvoice, err = service.stripeClient.Invoices().Update(stripeInvoice.ID, params)
		if err != nil {
			return nil, err
		}
	}

	return stripeInvoice, nil
}

// createInvoices creates invoices for Stripe customers.
func (service *Service) createInvoices(ctx context.Context, customers []Customer, period time.Time) (scheduled, draft int, err error) {
	defer mon.Task()(&ctx)(&err)

	limiter := sync2.NewLimiter(service.maxParallelCalls)
	var errGrp errs.Group
	var mu sync.Mutex

	for _, cus := range customers {
		cusID := cus.ID
		limiter.Go(ctx, func() {
			inv, err := service.createInvoice(ctx, cusID, period)
			if err != nil {
				mu.Lock()
				errGrp.Add(err)
				mu.Unlock()
				return
			}
			if inv != nil {
				mu.Lock()
				if inv.AutoAdvance {
					scheduled++
				} else {
					draft++
				}
				mu.Unlock()
			}
		})
	}

	limiter.Wait()

	return scheduled, draft, errGrp.Err()
}

// SetInvoiceStatus will set all open invoices within the specified date range to the requested status.
func (service *Service) SetInvoiceStatus(ctx context.Context, startPeriod, endPeriod time.Time, status string, dryRun bool) (err error) {
	defer mon.Task()(&ctx)(&err)

	switch stripe.InvoiceStatus(strings.ToLower(status)) {
	case stripe.InvoiceStatusUncollectible:
		err = service.iterateInvoicesInTimeRange(ctx, startPeriod, endPeriod, func(invoiceId string) error {
			service.log.Info("updating invoice status to uncollectible", zap.String("invoiceId", invoiceId))
			if !dryRun {
				_, err := service.stripeClient.Invoices().MarkUncollectible(invoiceId, &stripe.InvoiceMarkUncollectibleParams{})
				if err != nil {
					return Error.Wrap(err)
				}
			}
			return nil
		})
	case stripe.InvoiceStatusVoid:
		err = service.iterateInvoicesInTimeRange(ctx, startPeriod, endPeriod, func(invoiceId string) error {
			service.log.Info("updating invoice status to void", zap.String("invoiceId", invoiceId))
			if !dryRun {
				_, err = service.stripeClient.Invoices().VoidInvoice(invoiceId, &stripe.InvoiceVoidParams{})
				if err != nil {
					return Error.Wrap(err)
				}
			}
			return nil
		})
	case stripe.InvoiceStatusPaid:
		err = service.iterateInvoicesInTimeRange(ctx, startPeriod, endPeriod, func(invoiceId string) error {
			service.log.Info("updating invoice status to paid", zap.String("invoiceId", invoiceId))
			if !dryRun {
				payParams := &stripe.InvoicePayParams{
					Params:        stripe.Params{Context: ctx},
					PaidOutOfBand: stripe.Bool(true),
				}
				_, err = service.stripeClient.Invoices().Pay(invoiceId, payParams)
				if err != nil {
					return Error.Wrap(err)
				}
			}
			return nil
		})
	default:
		// unknown
		service.log.Error("Unknown status provided. Valid options are uncollectible, void, or paid.", zap.String("status", status))
		return Error.New("unknown status provided")
	}
	return err
}

func (service *Service) iterateInvoicesInTimeRange(ctx context.Context, startPeriod, endPeriod time.Time, updateStatus func(string) error) (err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.InvoiceListParams{
		ListParams: stripe.ListParams{
			Context: ctx,
			Limit:   stripe.Int64(100),
		},
		Status: stripe.String("open"),
		CreatedRange: &stripe.RangeQueryParams{
			GreaterThanOrEqual: startPeriod.Unix(),
			LesserThanOrEqual:  endPeriod.Unix(),
		},
	}

	numInvoices := 0
	invoicesIterator := service.stripeClient.Invoices().List(params)
	for invoicesIterator.Next() {
		numInvoices++
		stripeInvoice := invoicesIterator.Invoice()

		err := updateStatus(stripeInvoice.ID)
		if err != nil {
			return Error.Wrap(err)
		}
	}
	service.log.Info("found " + strconv.Itoa(numInvoices) + " total invoices")
	return Error.Wrap(invoicesIterator.Err())
}

// CreateBalanceInvoiceItems will find users with a stripe balance, create an invoice
// item with the charges due, and zero out the stripe balance.
func (service *Service) CreateBalanceInvoiceItems(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	custListParams := &stripe.CustomerListParams{
		ListParams: stripe.ListParams{
			Context: ctx,
			Limit:   stripe.Int64(100),
		},
	}

	var errGrp errs.Group
	itr := service.stripeClient.Customers().List(custListParams)
	for itr.Next() {
		if itr.Customer().Balance <= 0 {
			continue
		}
		service.log.Info("Creating invoice item for customer prior balance", zap.String("CustomerID", itr.Customer().ID))
		itemParams := &stripe.InvoiceItemParams{
			Params: stripe.Params{
				Context: ctx,
			},
			Currency:    stripe.String(string(stripe.CurrencyUSD)),
			Customer:    stripe.String(itr.Customer().ID),
			Description: stripe.String("Prior Stripe Customer Balance"),
			Quantity:    stripe.Int64(1),
			UnitAmount:  stripe.Int64(itr.Customer().Balance),
		}
		invoiceItem, err := service.stripeClient.InvoiceItems().New(itemParams)
		if err != nil {
			service.log.Error("Failed to add invoice item for customer prior balance", zap.Error(err))
			errGrp.Add(err)
			continue
		}
		service.log.Info("Updating customer balance to 0", zap.String("CustomerID", itr.Customer().ID))
		custParams := &stripe.CustomerParams{
			Params: stripe.Params{
				Context: ctx,
			},
			Balance:     stripe.Int64(0),
			Description: stripe.String("Customer balance adjusted to 0 after adding invoice item " + invoiceItem.ID),
		}
		_, err = service.stripeClient.Customers().Update(itr.Customer().ID, custParams)
		if err != nil {
			service.log.Error("Failed to update customer balance to 0 after adding invoice item", zap.Error(err))
			errGrp.Add(err)
			continue
		}
		service.log.Info("Customer successfully updated", zap.String("CustomerID", itr.Customer().ID), zap.Int64("Prior Balance", itr.Customer().Balance), zap.Int64("New Balance", 0), zap.String("InvoiceItemID", invoiceItem.ID))
	}
	if itr.Err() != nil {
		service.log.Error("Failed to create invoice items for all customers", zap.Error(itr.Err()))
		errGrp.Add(itr.Err())
	}
	return errGrp.Err()
}

// GenerateInvoices performs tasks necessary to generate Stripe invoices.
// This is equivalent to invoking PrepareInvoiceProjectRecords, InvoiceApplyProjectRecords,
// and CreateInvoices in order.
func (service *Service) GenerateInvoices(ctx context.Context, period time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	for _, subFn := range []struct {
		Description string
		Exec        func(context.Context, time.Time) error
	}{
		{"Preparing invoice project records", service.PrepareInvoiceProjectRecords},
		{"Applying invoice project records", service.InvoiceApplyProjectRecords},
		{"Creating invoices", service.CreateInvoices},
	} {
		service.log.Info(subFn.Description)
		if err := subFn.Exec(ctx, period); err != nil {
			return err
		}
	}

	return nil
}

// FinalizeInvoices transitions all draft invoices to open finalized invoices in stripe. No payment is to be collected yet.
func (service *Service) FinalizeInvoices(ctx context.Context) (err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.InvoiceListParams{
		ListParams: stripe.ListParams{Context: ctx},
		Status:     stripe.String("draft"),
	}

	invoicesIterator := service.stripeClient.Invoices().List(params)
	for invoicesIterator.Next() {
		stripeInvoice := invoicesIterator.Invoice()
		if stripeInvoice.AutoAdvance {
			continue
		}

		err := service.finalizeInvoice(ctx, stripeInvoice.ID)
		if err != nil {
			return Error.Wrap(err)
		}
	}

	return Error.Wrap(invoicesIterator.Err())
}

func (service *Service) finalizeInvoice(ctx context.Context, invoiceID string) (err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.InvoiceFinalizeParams{
		Params:      stripe.Params{Context: ctx},
		AutoAdvance: stripe.Bool(false),
	}
	_, err = service.stripeClient.Invoices().FinalizeInvoice(invoiceID, params)
	return err
}

// PayInvoices attempts to transition all open finalized invoices created on or after a certain time to "paid"
// by charging the customer according to subscriptions settings.
func (service *Service) PayInvoices(ctx context.Context, createdOnAfter time.Time) (err error) {
	defer mon.Task()(&ctx)(&err)

	params := &stripe.InvoiceListParams{
		ListParams: stripe.ListParams{Context: ctx},
		Status:     stripe.String("open"),
	}
	params.Filters.AddFilter("created", "gte", strconv.FormatInt(createdOnAfter.Unix(), 10))

	invoicesIterator := service.stripeClient.Invoices().List(params)
	for invoicesIterator.Next() {
		stripeInvoice := invoicesIterator.Invoice()
		if stripeInvoice.DueDate > 0 {
			service.log.Info("Skipping invoice marked for manual payment",
				zap.String("id", stripeInvoice.ID),
				zap.String("number", stripeInvoice.Number),
				zap.String("customer", stripeInvoice.Customer.ID))
			continue
		}

		params := &stripe.InvoicePayParams{Params: stripe.Params{Context: ctx}}
		_, err = service.stripeClient.Invoices().Pay(stripeInvoice.ID, params)
		if err != nil {
			service.log.Warn("unable to pay invoice",
				zap.String("stripe-invoice-id", stripeInvoice.ID),
				zap.Error(err))
			continue
		}
	}
	return invoicesIterator.Err()
}

// PayCustomerInvoices attempts to transition all open finalized invoices created on or after a certain time to "paid"
// by charging the customer according to subscriptions settings.
func (service *Service) PayCustomerInvoices(ctx context.Context, customerID string) (err error) {
	defer mon.Task()(&ctx)(&err)

	customerInvoices, err := service.getInvoices(ctx, customerID, time.Unix(0, 0))
	if err != nil {
		return Error.New("error getting invoices for stripe customer %s", customerID)
	}

	var errGrp errs.Group
	for _, customerInvoice := range customerInvoices {
		if customerInvoice.DueDate > 0 {
			service.log.Info("Skipping invoice marked for manual payment",
				zap.String("id", customerInvoice.ID),
				zap.String("number", customerInvoice.Number),
				zap.String("customer", customerInvoice.Customer.ID))
			continue
		}

		params := &stripe.InvoicePayParams{Params: stripe.Params{Context: ctx}}
		_, err = service.stripeClient.Invoices().Pay(customerInvoice.ID, params)
		if err != nil {
			errGrp.Add(Error.New("unable to pay invoice %s", customerInvoice.ID))
			continue
		}
	}
	return errGrp.Err()
}

// PayInvoicesWithTokenBalance attempts to transition all the users open invoices to "paid" by charging the customer
// token balance.
func (service *Service) PayInvoicesWithTokenBalance(ctx context.Context, userID uuid.UUID, cusID string, invoices []stripe.Invoice) (err error) {
	// get wallet
	wallet, err := service.walletsDB.GetWallet(ctx, userID)
	if err != nil {
		return Error.New("unable to get users in the wallets table")
	}

	return service.payInvoicesWithTokenBalance(ctx, cusID, storjscan.Wallet{
		UserID:  userID,
		Address: wallet,
	}, invoices)
}

// payInvoicesWithTokenBalance attempts to transition the users open invoices to "paid" by charging the customer
// token balance.
func (service *Service) payInvoicesWithTokenBalance(ctx context.Context, cusID string, wallet storjscan.Wallet, invoices []stripe.Invoice) (err error) {
	defer mon.Task()(&ctx)(&err)

	var errGrp errs.Group

	for _, invoice := range invoices {
		// if no balance due, do nothing
		if invoice.AmountRemaining <= 0 {
			continue
		}
		monetaryTokenBalance, err := service.billingDB.GetBalance(ctx, wallet.UserID)
		if err != nil {
			errGrp.Add(Error.New("unable to get balance for user ID %s", wallet.UserID.String()))
			continue
		}
		// truncate here since stripe only has cent level precision for invoices.
		// The users account balance will still maintain the full precision monetary value!
		tokenBalance := currency.AmountFromDecimal(monetaryTokenBalance.AsDecimal().Truncate(2), currency.USDollars)
		// if token balance is not > 0, don't bother with the rest
		if tokenBalance.BaseUnits() <= 0 {
			break
		}

		var tokenCreditAmount int64
		if invoice.AmountRemaining >= tokenBalance.BaseUnits() {
			tokenCreditAmount = tokenBalance.BaseUnits()
		} else {
			tokenCreditAmount = invoice.AmountRemaining
		}

		txID, err := service.createTokenPaymentBillingTransaction(ctx, wallet.UserID, invoice.ID, wallet.Address.Hex(), -tokenCreditAmount)
		if err != nil {
			errGrp.Add(Error.New("unable to create token payment billing transaction for user %s", wallet.UserID.String()))
			continue
		}

		creditNoteID, err := service.addCreditNoteToInvoice(ctx, invoice.ID, cusID, wallet.Address.Hex(), tokenCreditAmount, txID)
		if err != nil {
			errGrp.Add(Error.New("unable to create token payment credit note for user %s", wallet.UserID.String()))
			continue
		}

		metadata, err := json.Marshal(map[string]interface{}{
			"Credit Note ID": creditNoteID,
		})

		if err != nil {
			errGrp.Add(Error.New("unable to marshall credit note ID %s", creditNoteID))
			continue
		}

		err = service.billingDB.UpdateMetadata(ctx, txID, metadata)
		if err != nil {
			errGrp.Add(Error.New("unable to add credit note ID to billing transaction for user %s", wallet.UserID.String()))
			continue
		}

		err = service.billingDB.UpdateStatus(ctx, txID, billing.TransactionStatusCompleted)
		if err != nil {
			errGrp.Add(Error.New("unable to update status for billing transaction for user %s", wallet.UserID.String()))
			continue
		}
	}
	return errGrp.Err()
}

// projectUsagePrice represents pricing for project usage.
type projectUsagePrice struct {
	Storage  decimal.Decimal
	Egress   decimal.Decimal
	Segments decimal.Decimal
}

// Total returns project usage price total.
func (price projectUsagePrice) Total() decimal.Decimal {
	return price.Storage.Add(price.Egress).Add(price.Segments)
}

// Total returns project usage price total.
func (price projectUsagePrice) TotalInt64() int64 {
	return price.Storage.Add(price.Egress).Add(price.Segments).IntPart()
}

// calculateProjectUsagePrice calculate project usage price.
func (service *Service) calculateProjectUsagePrice(usage accounting.ProjectUsage, pricing payments.ProjectUsagePriceModel) projectUsagePrice {
	return projectUsagePrice{
		Storage:  pricing.StorageMBMonthCents.Mul(storageMBMonthDecimal(usage.Storage)).Round(0),
		Egress:   pricing.EgressMBCents.Mul(egressMBDecimal(usage.Egress)).Round(0),
		Segments: pricing.SegmentMonthCents.Mul(segmentMonthDecimal(usage.SegmentCount)).Round(0),
	}
}

// SetNow allows tests to have the Service act as if the current time is whatever
// they want. This avoids races and sleeping, making tests more reliable and efficient.
func (service *Service) SetNow(now func() time.Time) {
	service.nowFn = now
}

// storageMBMonthDecimal converts storage usage from Byte-Hours to Megabyte-Months.
// The result is rounded to the nearest whole number, but returned as Decimal for convenience.
func storageMBMonthDecimal(storage float64) decimal.Decimal {
	return decimal.NewFromFloat(storage).Shift(-6).Div(decimal.NewFromInt(hoursPerMonth)).Round(0)
}

// egressMBDecimal converts egress usage from bytes to Megabytes
// The result is rounded to the nearest whole number, but returned as Decimal for convenience.
func egressMBDecimal(egress int64) decimal.Decimal {
	return decimal.NewFromInt(egress).Shift(-6).Round(0)
}

// segmentMonthDecimal converts segments usage from Segment-Hours to Segment-Months.
// The result is rounded to the nearest whole number, but returned as Decimal for convenience.
func segmentMonthDecimal(segments float64) decimal.Decimal {
	return decimal.NewFromFloat(segments).Div(decimal.NewFromInt(hoursPerMonth)).Round(0)
}

// doesProjectRecordHaveNoUsage returns true if the given project record
// represents a billing cycle where there was no usage.
func doesProjectRecordHaveNoUsage(record ProjectRecord) bool {
	return record.Storage == 0 && record.Egress == 0 && record.Segments == 0
}

// applyEgressDiscount returns the amount of egress that we should charge for by subtracting
// the discounted amount.
func applyEgressDiscount(usage accounting.ProjectUsage, model payments.ProjectUsagePriceModel) int64 {
	egress := usage.Egress - int64(math.Round(usage.Storage/hoursPerMonth*model.EgressDiscountRatio))
	if egress < 0 {
		egress = 0
	}
	return egress
}
