// ========================================
// MAIN.JS - Coordenador Principal
// ========================================

/**
 * Inicialização quando o DOM estiver carregado
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('Sistema de Criptografia carregado.');
    
    // Configurar event listeners para mostrar/ocultar IV baseado no modo AES
    configurarEventListenersAES();
});

/**
 * Configura os event listeners para o AES
 */
function configurarEventListenersAES() {
    // Mostrar/ocultar IV baseado no modo AES (Cifrar)
    const modosCifragem = document.querySelectorAll('input[name="aesMode"]');
    if (modosCifragem.length > 0) {
        modosCifragem.forEach(radio => {
            radio.addEventListener('change', function() {
                const ivContainer = document.getElementById('aesIvInputContainer');
                if (ivContainer) {
                    ivContainer.style.display = this.value === 'CBC' ? 'block' : 'none';
                }
            });
        });
    }
    
    // Mostrar/ocultar IV baseado no modo AES (Decifrar)
    const modosDecifragem = document.querySelectorAll('input[name="aesDecMode"]');
    if (modosDecifragem.length > 0) {
        modosDecifragem.forEach(radio => {
            radio.addEventListener('change', function() {
                const ivContainer = document.getElementById('aesDecIvContainer');
                if (ivContainer) {
                    ivContainer.style.display = this.value === 'CBC' ? 'block' : 'none';
                }
            });
        });
    }
}

/**
 * Alterna entre as seções principais (abas principais do sistema)
 * @param {string} secaoId - ID da seção a ser mostrada
 */
function mostrarSecao(secaoId) {
    // Esconder todas as seções
    document.querySelectorAll('.section').forEach(secao => {
        secao.classList.remove('active');
    });
    
    // Remover active de todos os botões de navegação
    document.querySelectorAll('.tab-nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Mostrar seção selecionada
    const secaoSelecionada = document.getElementById(secaoId);
    if (secaoSelecionada) {
        secaoSelecionada.classList.add('active');
    }
    
    // Adicionar active ao botão correspondente (o event.target)
    // Nota: Esta função é chamada via onclick no HTML, então event está disponível
    if (typeof event !== 'undefined' && event.target) {
        event.target.classList.add('active');
    }
}
