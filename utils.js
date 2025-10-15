// ========================================
// UTILS.JS - Funções Auxiliares
// ========================================

/**
 * Lê o conteúdo de um arquivo de texto
 * @param {File} file - Arquivo a ser lido
 * @returns {Promise<string>} - Conteúdo do arquivo
 */
function lerArquivoTexto(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = function(event) {
            resolve(event.target.result);
        };
        reader.onerror = function() {
            reject('Erro ao ler o arquivo.');
        };
        reader.readAsText(file);
    });
}

/**
 * Faz download de um arquivo
 * @param {string} conteudo - Conteúdo do arquivo
 * @param {string} nomeArquivo - Nome do arquivo para download
 */
function baixarArquivo(conteudo, nomeArquivo) {
    const blob = new Blob([conteudo], {type: 'text/plain'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = nomeArquivo;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Mostra mensagem de erro
 * @param {string} mensagem - Mensagem de erro
 */
function mostrarErro(mensagem) {
    // Verificar se é erro de biblioteca não carregada
    if (mensagem.includes('forge is not defined') || 
        mensagem.includes('forge não está definido') ||
        mensagem.includes('Cannot read property') ||
        mensagem.includes('Cannot read properties of undefined')) {
        mensagem = '🔄 Biblioteca de criptografia não carregada.\n\n' +
                   'A página será recarregada automaticamente...\n\n' +
                   'Se o problema persistir:\n' +
                   '• Verifique sua conexão com a internet\n' +
                   '• Desative bloqueadores de anúncios\n' +
                   '• Tente outro navegador';
        
        // Tentar recarregar automaticamente após 2 segundos
        setTimeout(() => {
            if (typeof forge === 'undefined') {
                location.reload();
            }
        }, 2000);
    }
    
    alert('❌ Erro: ' + mensagem);
    console.error('❌ Erro:', mensagem);
}

/**
 * Mostra mensagem de sucesso
 * @param {string} mensagem - Mensagem de sucesso
 */
function mostrarSucesso(mensagem) {
    console.log('✓ ' + mensagem);
}
