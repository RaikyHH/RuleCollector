document.addEventListener('DOMContentLoaded', function() {
    const copyButton = document.getElementById('copyRuleButton');

    if (copyButton) {
        // Speichere das ursprüngliche Icon und den Text einmalig
        const originalButtonIcon = copyButton.querySelector('.icon-copy') ? copyButton.querySelector('.icon-copy').outerHTML : '';
        const originalButtonText = copyButton.querySelector('.btn-copy-text') ? copyButton.querySelector('.btn-copy-text').innerText : 'Kopieren';

        copyButton.addEventListener('click', function() {
            const ruleContentElement = document.getElementById('ruleYamlContent'); // ID verwenden

            if (ruleContentElement) {
                const ruleText = ruleContentElement.innerText; // .innerText ist hier besser für <pre><code>
                navigator.clipboard.writeText(ruleText).then(function() {
                    // Erfolgsfeedback
                    if(copyButton.querySelector('.btn-copy-text')) {
                        copyButton.querySelector('.btn-copy-text').innerText = 'Kopiert!';
                    } else { // Fallback falls span nicht da
                        copyButton.innerHTML = originalButtonIcon + " Kopiert!";
                    }
                    copyButton.disabled = true;

                    setTimeout(function() {
                        if(copyButton.querySelector('.btn-copy-text')) {
                            copyButton.querySelector('.btn-copy-text').innerText = originalButtonText;
                        } else {
                             copyButton.innerHTML = originalButtonIcon + " " + originalButtonText;
                        }
                        copyButton.disabled = false;
                    }, 2000); // Nach 2 Sekunden zurücksetzen
                }).catch(function(err) {
                    console.error('Fehler beim Kopieren des Textes: ', err);
                    // Optional: Fehlerfeedback für den Benutzer
                    const tempErrorText = 'Fehler!';
                    if(copyButton.querySelector('.btn-copy-text')) {
                        copyButton.querySelector('.btn-copy-text').innerText = tempErrorText;
                    } else {
                        copyButton.innerHTML = originalButtonIcon + " " + tempErrorText;
                    }
                     setTimeout(function() {
                        if(copyButton.querySelector('.btn-copy-text')) {
                            copyButton.querySelector('.btn-copy-text').innerText = originalButtonText;
                        } else {
                            copyButton.innerHTML = originalButtonIcon + " " + originalButtonText;
                        }
                    }, 2000);
                });
            } else {
                console.error('Regelelement mit ID "ruleYamlContent" nicht gefunden.');
            }
        });
    }
});