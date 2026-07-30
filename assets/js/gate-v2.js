// Dane z serwera przychodza wyspa JSON w HTML (patrz json_island()).
const G = JSON.parse(document.getElementById('bb-gate').textContent);
document.getElementById('pwdForm').addEventListener('submit', function() {
    this.action = '/' + G.slug + window.location.hash;
});
