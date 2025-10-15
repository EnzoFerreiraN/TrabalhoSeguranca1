// ========================================
// RSA-KEYS.JS - Geração de Chaves RSA
// ========================================

/**
 * Gera um par de chaves RSA (pública e privada)
 * Compatível com o padrão OpenSSL
 * Usa node-forge se disponível, senão usa Web Crypto API nativa
 */
async function gerarChavesRSA() {
    try {
        // Busca o radio button selecionado pelo name
        const keySizeElement = document.querySelector('input[name="keySize"]:checked');
        if (!keySizeElement) {
            throw new Error('Selecione um tamanho de chave.');
        }
        const keySize = parseInt(keySizeElement.value);
        console.log(`Gerando par de chaves RSA de ${keySize} bits...`);
        
        let publicKeyPem, privateKeyPem;
        
        // Tentar usar node-forge primeiro
        if (typeof forge !== 'undefined') {
            console.log('Usando node-forge...');
            const rsaKeyPair = forge.pki.rsa.generateKeyPair({ 
                bits: keySize, 
                e: 0x10001 
            });
            publicKeyPem = forge.pki.publicKeyToPem(rsaKeyPair.publicKey);
            privateKeyPem = forge.pki.privateKeyToPem(rsaKeyPair.privateKey);
        } 
        // Fallback para Web Crypto API nativa
        else if (typeof gerarChavesRSANativo !== 'undefined') {
            console.log('Usando Web Crypto API nativa...');
            const keyPair = await gerarChavesRSANativo(keySize);
            publicKeyPem = keyPair.publicKeyPem;
            privateKeyPem = keyPair.privateKeyPem;
        } 
        else {
            throw new Error('Nenhuma biblioteca de criptografia disponível.');
        }
        
        // Exibir as chaves nos campos de texto
        document.getElementById('publicKey').value = publicKeyPem;
        document.getElementById('privateKey').value = privateKeyPem;
        
        mostrarSucesso('Par de chaves RSA gerado com sucesso!');
    } catch (error) {
        mostrarErro('Erro ao gerar chaves RSA: ' + error.message);
    }
}

/**
 * Faz download da chave pública
 */
function baixarChavePublica() {
    const conteudo = document.getElementById('publicKey').value;
    if (!conteudo) {
        mostrarErro('Nenhuma chave pública disponível para download.');
        return;
    }
    baixarArquivo(conteudo, 'chave_publica.pem');
}

/**
 * Faz download da chave privada
 */
function baixarChavePrivada() {
    const conteudo = document.getElementById('privateKey').value;
    if (!conteudo) {
        mostrarErro('Nenhuma chave privada disponível para download.');
        return;
    }
    baixarArquivo(conteudo, 'chave_privada.pem');
}

/**
 * Função auxiliar para baixar qualquer chave
 * @param {string} idElemento - ID do elemento contendo a chave
 * @param {string} nomeArquivo - Nome do arquivo para download
 */
function baixarChave(idElemento, nomeArquivo) {
    const conteudo = document.getElementById(idElemento).value;
    if (!conteudo) {
        mostrarErro('Nenhuma chave disponível para download.');
        return;
    }
    baixarArquivo(conteudo, nomeArquivo);
}
