<template>
  <header id="dashboard-header">
    <div class="container-fluid">
      <div class="row">
        <div class="col-lg-4 col-md-6 col-2 align-self-center">
          <div class="hamburger-wrapper">
            <div class="hamburger-menu">
              <i class="fa-solid fa-bars" @click="openSidebar"></i>
            </div>
            <div class="form search-form">
              <div class="form-group">
                <input type="text" class="form-control" placeholder="Search">
                <img src="../assets/images/icons/search-black-icon.svg" class="icon" alt="icon">
              </div>
            </div>
          </div>
        </div>
        <div class="col-lg-8 col-md-6 col-10 align-self-center">
          <ul class="dashboard-options">
            <li>
              <a href="#">
                <span class="language">
                  <img src="../assets/images/icons/country-flag-icon.svg" alt="img">
                </span>
              </a>
            </li>
            <li>
              <a href="#">
                <span class="switch-theme">
                  <img src="../assets/images/icons/moon-black-icon.svg" alt="img">
                </span>
              </a>
            </li>
            <li>
              <a href="#">
                <span class="notification">
                  <img src="../assets/images/icons/notification-bell-black-icon.svg" alt="img">
                </span>
              </a>
            </li>
            <li>
              <a href="#">
                <span class="user-img">
                  J
                </span>
              </a>
            </li>
            <li>
              <a href="#" class="btn-style large icon text"><img src="../assets/images/icons/logout-black-icon.svg" alt="icon">Log Out</a>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </header>
</template>

<script>
// @ is an alias to /src


export default {
  name: 'DashboardHeader',
  components: {
  },
  data(){
    return{
      isMenuActive: false,
    }
  },
  methods:{
    openSidebar() {
      this.$emit('openSidebar')
    },
    handleSCroll() {
      let header = document.querySelector("header");
      if (window.scrollY >= 50 && !header.className.includes('sticky')) {
        header.classList.add('sticky');
      } else if (window.scrollY <= 50) {
        header.classList.remove('sticky');
      }
    }
  },
  created() {
    window.addEventListener('scroll', this.handleSCroll);
  },
  unmounted() {
    window.removeEventListener('scroll', this.handleSCroll);
  }
}
</script>
