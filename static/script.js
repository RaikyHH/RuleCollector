// Momentan wird die Seite bei Klick neu geladen.
// Wenn Sie AJAX-basierte Updates wünschen, würde hier JavaScript-Code stehen,
// um /api/rule/<id> abzurufen und die Bereiche dynamisch zu füllen.
// Beispiel (nicht voll funktionsfähig ohne Anpassungen im HTML):

/*
document.addEventListener('DOMContentLoaded', function() {
    const ruleLinks = document.querySelectorAll('.rule-list a');
    const ruleDisplayArea = document.querySelector('.rule-display-area pre code');
    const metadataTableBody = document.querySelector('.metadata-table tbody'); // Braucht tbody im HTML

    ruleLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault();
            const ruleId = this.getAttribute('data-id'); // Müsste im HTML hinzugefügt werden

            // Aktiven Link markieren
            document.querySelectorAll('.rule-list li.active').forEach(li => li.classList.remove('active'));
            this.parentElement.classList.add('active');

            fetch(`/api/rule/${ruleId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        ruleDisplayArea.textContent = data.error;
                        metadataTableBody.innerHTML = ''; // Clear metadata
                        return;
                    }
                    ruleDisplayArea.textContent = data.raw_rule;
                    // Metadaten füllen (Beispiel)
                    let metaHtml = `
                        <tr><th>ID</th><td>${data.id}</td></tr>
                        <tr><th>Title</th><td>${data.title}</td></tr>
                        // ... weitere Felder
                    `;
                    metadataTableBody.innerHTML = metaHtml;
                })
                .catch(error => {
                    console.error('Error fetching rule:', error);
                    ruleDisplayArea.textContent = 'Fehler beim Laden der Regel.';
                });
        });
    });
});
*/