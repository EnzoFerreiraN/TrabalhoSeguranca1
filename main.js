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
    
    // Garantir que a inicialização seja executada novamente após um pequeno delay
    // (caso os elementos ainda não estejam completamente renderizados)
    setTimeout(function() {
        console.log('🔄 Reinicializando event listeners AES (fallback)...');
        configurarEventListenersAES();
    }, 500);
});

/**
 * Configura os event listeners para o AES
 */
function configurarEventListenersAES() {
    console.log('🔧 Configurando event listeners AES...');
    
    // Mostrar/ocultar IV baseado no modo AES (Cifrar)
    const modosCifragem = document.querySelectorAll('input[name="aesMode"]');
    console.log('📍 Modos de cifragem encontrados:', modosCifragem.length);
    
    if (modosCifragem.length > 0) {
        modosCifragem.forEach(radio => {
            radio.addEventListener('change', function() {
                console.log('🔄 Radio change detectado! Valor:', this.value);
                const ivContainer = document.getElementById('aesIvInputContainer');
                if (ivContainer) {
                    const novoDisplay = this.value === 'CBC' ? 'block' : 'none';
                    ivContainer.style.display = novoDisplay;
                    console.log('🔄 Modo cifragem alterado para:', this.value, '| IV display:', novoDisplay);
                } else {
                    console.error('❌ IV Container (cifragem) não encontrado!');
                }
            });
            
            // Adicionar também listener de 'click' como fallback
            radio.addEventListener('click', function() {
                console.log('🖱️ Radio click detectado! Valor:', this.value);
                const ivContainer = document.getElementById('aesIvInputContainer');
                if (ivContainer) {
                    const novoDisplay = this.value === 'CBC' ? 'block' : 'none';
                    ivContainer.style.display = novoDisplay;
                    console.log('🖱️ Click processado:', this.value, '| IV display:', novoDisplay);
                }
            });
        });
        
        // Inicializar estado do IV na cifragem
        const modoCifragemSelecionado = document.querySelector('input[name="aesMode"]:checked');
        if (modoCifragemSelecionado) {
            const ivContainer = document.getElementById('aesIvInputContainer');
            if (ivContainer) {
                ivContainer.style.display = modoCifragemSelecionado.value === 'CBC' ? 'block' : 'none';
                console.log('✅ Estado inicial cifragem:', modoCifragemSelecionado.value, '| IV display:', ivContainer.style.display);
            }
        }
    }
    
    // Mostrar/ocultar IV baseado no modo AES (Decifrar)
    const modosDecifragem = document.querySelectorAll('input[name="aesDecMode"]');
    console.log('📍 Modos de decifragem encontrados:', modosDecifragem.length);
    
    if (modosDecifragem.length > 0) {
        modosDecifragem.forEach(radio => {
            radio.addEventListener('change', function() {
                console.log('🔄 Radio change detectado! Valor:', this.value);
                const ivContainer = document.getElementById('aesDecIvContainer');
                if (ivContainer) {
                    const novoDisplay = this.value === 'CBC' ? 'block' : 'none';
                    ivContainer.style.display = novoDisplay;
                    console.log('🔄 Modo decifragem alterado para:', this.value, '| IV display:', novoDisplay);
                } else {
                    console.error('❌ IV Container não encontrado!');
                }
            });
            
            // Adicionar também listener de 'click' como fallback
            radio.addEventListener('click', function() {
                console.log('🖱️ Radio click detectado! Valor:', this.value);
                const ivContainer = document.getElementById('aesDecIvContainer');
                if (ivContainer) {
                    const novoDisplay = this.value === 'CBC' ? 'block' : 'none';
                    ivContainer.style.display = novoDisplay;
                    console.log('🖱️ Click processado:', this.value, '| IV display:', novoDisplay);
                }
            });
        });
        
        // Inicializar estado do IV na decifragem
        const modoDecifragemSelecionado = document.querySelector('input[name="aesDecMode"]:checked');
        console.log('📍 Modo decifragem selecionado:', modoDecifragemSelecionado ? modoDecifragemSelecionado.value : 'NENHUM');
        
        if (modoDecifragemSelecionado) {
            const ivContainer = document.getElementById('aesDecIvContainer');
            console.log('📍 IV Container encontrado:', ivContainer ? 'SIM' : 'NÃO');
            
            if (ivContainer) {
                ivContainer.style.display = modoDecifragemSelecionado.value === 'CBC' ? 'block' : 'none';
                console.log('✅ Estado inicial decifragem:', modoDecifragemSelecionado.value, '| IV display:', ivContainer.style.display);
            }
        }
    }
    
    console.log('✅ Configuração de event listeners AES concluída.');
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
    
    // Se mudou para a seção de decifragem AES, reconfigurar visibilidade do IV
    if (secaoId === 'secaoAESDec') {
        console.log('🔄 Entrando na seção de decifragem AES, ajustando visibilidade do IV...');
        setTimeout(function() {
            const modoSelecionado = document.querySelector('input[name="aesDecMode"]:checked');
            const ivContainer = document.getElementById('aesDecIvContainer');
            
            if (modoSelecionado && ivContainer) {
                ivContainer.style.display = modoSelecionado.value === 'CBC' ? 'block' : 'none';
                console.log('✅ IV ajustado:', modoSelecionado.value, '| Display:', ivContainer.style.display);
            }
        }, 100);
    }
}
