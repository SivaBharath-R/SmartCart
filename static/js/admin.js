document.addEventListener("DOMContentLoaded", function(){

    const toggleBtn = document.getElementById("toggleBtn");
    const sidebar = document.getElementById("sidebar");
    const main = document.querySelector(".main");
    const overlay = document.getElementById("overlay");

    if(!toggleBtn || !sidebar || !overlay) return;

    function isMobile(){
        return window.innerWidth <= 768;
    }

    function openMenu(){
        if(isMobile()){
            sidebar.classList.add("open");
            overlay.classList.add("show");
        }else{
            sidebar.classList.remove("closed");
            main.classList.remove("expand");
        }
    }

    function closeMenu(){
        if(isMobile()){
            sidebar.classList.remove("open");
            overlay.classList.remove("show");
        }else{
            sidebar.classList.add("closed");
            main.classList.add("expand");
        }
    }

    function toggleMenu(){
        if(isMobile()){
            sidebar.classList.contains("open") ? closeMenu() : openMenu();
        }else{
            sidebar.classList.contains("closed") ? openMenu() : closeMenu();
        }
    }

    toggleBtn.addEventListener("click", function(e){
        e.stopPropagation();
        toggleMenu();
    });

    // mobile outside click
    overlay.addEventListener("click", closeMenu);

});
