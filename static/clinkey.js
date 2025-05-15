// Fonction pour toggle le mot de passe en clair/masqué
function togglePasswordVisibility(pwField, toggleBtn) {
    if (pwField.type === "password") {
        pwField.type = "text";
        toggleBtn.textContent = "Hide";
    } else {
        pwField.type = "password";
        toggleBtn.textContent = "Show";
    }
}

// Ajoute l'événement sur tous les boutons "Afficher" de la liste pour révéler/masquer le mot de passe
const revealButtons = document.querySelectorAll('.reveal-btn');
revealButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        // Le champ input de mot de passe est le sibling précédent du bouton dans la cellule
        const pwdField = btn.closest('tr').querySelector('.pwd-field');
        if (pwdField) {
            togglePasswordVisibility(pwdField, btn);
        }
    });
});
