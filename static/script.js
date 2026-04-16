document.addEventListener('DOMContentLoaded', () => {
    const copyButton = document.getElementById('copyRuleButton');
    const ruleContentElement = document.getElementById('ruleYamlContent');

    // Exit if the necessary elements don't exist on the page
    if (!copyButton || !ruleContentElement) {
        return;
    }

    const buttonTextSpan = copyButton.querySelector('.btn-copy-text');
    const originalButtonText = buttonTextSpan ? buttonTextSpan.textContent : 'Copy';

    /**
     * Updates the button's appearance and state.
     * @param {string} text - The text to display on the button.
     * @param {string} state - The state ('success', 'error', or 'reset').
     */
    const setButtonState = (text, state) => {
        if (buttonTextSpan) {
            buttonTextSpan.textContent = text;
        }
        
        copyButton.disabled = (state !== 'reset');
        
        copyButton.classList.remove('is-success', 'is-error');
        if (state === 'success') {
            copyButton.classList.add('is-success');
        } else if (state === 'error') {
            copyButton.classList.add('is-error');
        }
    };

    copyButton.addEventListener('click', () => {
        const ruleText = ruleContentElement.textContent;

        navigator.clipboard.writeText(ruleText).then(() => {
            // --- Success ---
            setButtonState('Copied!', 'success');
            
            setTimeout(() => {
                setButtonState(originalButtonText, 'reset');
            }, 2000); // Reset after 2 seconds

        }).catch(err => {
            // --- Error ---
            console.error('Failed to copy text: ', err);
            setButtonState('Error!', 'error');

            setTimeout(() => {
                setButtonState(originalButtonText, 'reset');
            }, 2000); // Reset after 2 seconds
        });
    });
});