document.addEventListener('DOMContentLoaded', function() {
    const printButton = document.createElement('button');
    printButton.className = 'print-button';
    printButton.textContent = 'Download PDF';
    printButton.onclick = () => window.print();
    document.body.appendChild(printButton);
});