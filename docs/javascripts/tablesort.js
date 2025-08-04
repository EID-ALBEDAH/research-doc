/* docs/javascripts/tablesort.js */
// Enhanced table sorting for research data

document.addEventListener('DOMContentLoaded', function() {
  // Initialize tablesort on all tables with class 'sortable'
  const tables = document.querySelectorAll('table.sortable');
  tables.forEach(table => {
    new Tablesort(table);
  });
  
  // Add sortable class to all tables by default
  const allTables = document.querySelectorAll('table');
  allTables.forEach(table => {
    if (!table.classList.contains('no-sort')) {
      table.classList.add('sortable');
      new Tablesort(table);
    }
  });
  
  // Research progress tracking
  const progressBars = document.querySelectorAll('.progress-bar');
  progressBars.forEach(bar => {
    const progress = bar.dataset.progress || 0;
    const fill = bar.querySelector('.progress-fill');
    if (fill) {
      fill.style.width = progress + '%';
    }
  });
  
  // Status indicators animation
  const statusIndicators = document.querySelectorAll('.status-indicator');
  statusIndicators.forEach(indicator => {
    indicator.addEventListener('click', function() {
      this.style.transform = 'scale(1.1)';
      setTimeout(() => {
        this.style.transform = 'scale(1)';
      }, 200);
    });
  });
});

// Research metrics counter animation
function animateCounter(element, target) {
  let current = 0;
  const increment = target / 100;
  const timer = setInterval(() => {
    current += increment;
    element.textContent = Math.floor(current).toLocaleString();
    if (current >= target) {
      element.textContent = target.toLocaleString();
      clearInterval(timer);
    }
  }, 20);
}

// Initialize counters when they come into view
const observerOptions = {
  threshold: 0.1,
  rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const counter = entry.target.querySelector('.metric-value');
      if (counter && !counter.dataset.animated) {
        const target = parseInt(counter.dataset.target || counter.textContent.replace(/,/g, ''));
        animateCounter(counter, target);
        counter.dataset.animated = 'true';
      }
    }
  });
}, observerOptions);

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.metric-card').forEach(card => {
    observer.observe(card);
  });
});
