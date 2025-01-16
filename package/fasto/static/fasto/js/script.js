/*Nav burger*/
const navLinks = document.querySelector('.nav-links');
const burger = document.querySelector('.burger');
const main = document.querySelector('main');
const footer = document.querySelector('footer');
const body = document.querySelector('body');

burger.addEventListener('click', function() {
  navLinks.classList.toggle('show');

  if (window.innerWidth <= 1200) { // Vérifie si l'écran fait 500px ou moins
    if (navLinks.classList.contains('show')) {
      main.style.display = 'none';
      footer.style.display = 'none';
      body.style.backgroundColor = '#2f3061'
    } else {
      main.style.display = 'block';
      footer.style.display = 'block';
      body.style.backgroundColor = '#fff'
    }
  }
});


/*Animation*/
document.addEventListener("DOMContentLoaded", function() {
  const heroContent = document.querySelector(".hero-content");
  setTimeout(() => {
    heroContent.classList.add("visible");
  }, 500); // Délai avant le début de l'animation
});



// Section n°5


let canvas, ctx;
let dots = [];
let numDots = 100;

window.onload = function() {
    canvas = document.createElement('canvas');
    document.querySelector('.animated-background').appendChild(canvas);
    ctx = canvas.getContext('2d');

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    for (let i = 0; i < numDots; i++) {
        dots.push(new Dot());
    }

    animate();
};

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    dots.forEach(dot => dot.update());
    requestAnimationFrame(animate);
}

function Dot() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.vx = (Math.random() - 0.5) * 0.5;
    this.vy = (Math.random() - 0.5) * 0.5;
    this.radius = Math.random() * 2 + 1;

    this.update = function() {
        this.x += this.vx;
        this.y += this.vy;

        if (this.x > canvas.width || this.x < 0) this.vx = -this.vx;
        if (this.y > canvas.height || this.y < 0) this.vy = -this.vy;

        this.draw();
    };

    this.draw = function() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
        ctx.fill();
        ctx.closePath();
    };
}





document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', function() {
    document.querySelector('.tab.active').classList.remove('active');
    this.classList.add('active');

    document.querySelector('.tab-pane.active').classList.remove('active');
    const index = Array.from(this.parentNode.children).indexOf(this);
    document.querySelectorAll('.tab-pane')[index].classList.add('active');
  });
});


f