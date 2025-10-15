// ========================================
// RSA-SIGNATURE.JS - Assinatura e Verificação RSA
// ========================================

// Variável para armazenar a última assinatura
let lastSignature = null;

/**
 * Alterna entre as abas de chave (Texto/Arquivo) para assinatura
 */
function alternarAbaAssinatura(tipo, tab) {
    if (tipo === 'Key') {
        document.getElementById('tabSignKeyText').classList.remove('active');
        document.getElementById('tabSignKeyFile').classList.remove('active');
        document.getElementById('contentSignKeyText').classList.remove('active');
        document.getElementById('contentSignKeyFile').classList.remove('active');
        
        document.getElementById('tabSignKey' + tab).classList.add('active');
        document.getElementById('contentSignKey' + tab).classList.add('active');
    } else { // Content
        document.getElementById('tabSignContentText').classList.remove('active');
        document.getElementById('tabSignContentFile').classList.remove('active');
        document.getElementById('contentSignContentText').classList.remove('active');
        document.getElementById('contentSignContentFile').classList.remove('active');
        
        document.getElementById('tabSignContent' + tab).classList.add('active');
        document.getElementById('contentSignContent' + tab).classList.add('active');
    }
}

/**
 * Alterna entre as abas de chave (Texto/Arquivo) para verificação
 */
function alternarAbaVerificacao(tipo, tab) {
    if (tipo === 'Key') {
        document.getElementById('tabVerifyKeyText').classList.remove('active');
        document.getElementById('tabVerifyKeyFile').classList.remove('active');
        document.getElementById('contentVerifyKeyText').classList.remove('active');
        document.getElementById('contentVerifyKeyFile').classList.remove('active');
        
        document.getElementById('tabVerifyKey' + tab).classList.add('active');
        document.getElementById('contentVerifyKey' + tab).classList.add('active');
    } else { // Content
        document.getElementById('tabVerifyContentText').classList.remove('active');
        document.getElementById('tabVerifyContentFile').classList.remove('active');
        document.getElementById('contentVerifyContentText').classList.remove('active');
        document.getElementById('contentVerifyContentFile').classList.remove('active');
        
        document.getElementById('tabVerifyContent' + tab).classList.add('active');
        document.getElementById('contentVerifyContent' + tab).classList.add('active');
    }
}

/**
 * Cria uma assinatura digital RSA
 */
async function assinarMensagem() {
    console.log('Iniciando assinatura RSA...');
    
    try {
        // 1. Obter a chave privada
        const keyFileInput = document.getElementById('signKeyFile');
        const keyTextInput = document.getElementById('signKeyText').value.trim();
        
        if (!keyFileInput.files.length && !keyTextInput) {
            mostrarErro('Por favor, carregue a chave privada (.pem) ou cole no campo de texto.');
            return;
        }
        
        let privateKey;
        if (keyFileInput.files.length) {
            const pemContent = await lerArquivoTexto(keyFileInput.files[0]);
            privateKey = forge.pki.privateKeyFromPem(pemContent);
        } else {
            privateKey = forge.pki.privateKeyFromPem(keyTextInput);
        }
        
        // 2. Obter o conteúdo para assinar
        let content;
        if (document.getElementById('tabSignContentText').classList.contains('active')) {
            content = document.getElementById('signContentText').value.trim();
            if (!content) {
                mostrarErro('Por favor, digite o conteúdo para assinar.');
                return;
            }
        } else {
            const fileInput = document.getElementById('signContentFile');
            if (!fileInput.files.length) {
                mostrarErro('Por favor, selecione um arquivo para assinar.');
                return;
            }
            content = await lerArquivoTexto(fileInput.files[0]);
        }
        
        // 3. Obter configurações
        const shaVersion = document.querySelector('input[name="shaVersion"]:checked').value;
        const outputFormat = document.querySelector('input[name="signOutputFormat"]:checked').value;
        
        // 4. Criar o hash do conteúdo
        let md;
        switch (shaVersion) {
            case '256':
                md = forge.md.sha256.create();
                break;
            case '384':
                md = forge.md.sha384.create();
                break;
            case '512':
                md = forge.md.sha512.create();
                break;
            default:
                mostrarErro('Versão de SHA inválida.');
                return;
        }
        
        md.update(content, 'utf8');
        
        // 5. Assinar o hash
        const signature = privateKey.sign(md);
        
        // 6. Formatar a assinatura
        let formattedSignature;
        if (outputFormat === 'BASE64') {
            formattedSignature = forge.util.encode64(signature);
        } else { // HEX
            formattedSignature = forge.util.bytesToHex(signature);
        }
        
        lastSignature = formattedSignature;
        
        // 7. Exibir resultado
        document.getElementById('signatureOutput').textContent = formattedSignature;
        
        mostrarSucesso('Assinatura RSA criada com sucesso!');
        
    } catch (error) {
        mostrarErro('Erro ao criar assinatura: ' + error.message);
    }
}

/**
 * Verifica uma assinatura digital RSA
 */
async function verificarAssinatura() {
    console.log('Iniciando verificação de assinatura RSA...');
    
    try {
        // 1. Obter a chave pública
        const keyFileInput = document.getElementById('verifyKeyFile');
        const keyTextInput = document.getElementById('verifyKeyText').value.trim();
        
        if (!keyFileInput.files.length && !keyTextInput) {
            mostrarErro('Por favor, carregue a chave pública (.pem) ou cole no campo de texto.');
            return;
        }
        
        let publicKey;
        if (keyFileInput.files.length) {
            const pemContent = await lerArquivoTexto(keyFileInput.files[0]);
            publicKey = forge.pki.publicKeyFromPem(pemContent);
        } else {
            publicKey = forge.pki.publicKeyFromPem(keyTextInput);
        }
        
        // 2. Obter o conteúdo original
        let content;
        if (document.getElementById('tabVerifyContentText').classList.contains('active')) {
            content = document.getElementById('verifyContentText').value.trim();
            if (!content) {
                mostrarErro('Por favor, digite o conteúdo original.');
                return;
            }
        } else {
            const fileInput = document.getElementById('verifyContentFile');
            if (!fileInput.files.length) {
                mostrarErro('Por favor, selecione o arquivo com o conteúdo original.');
                return;
            }
            content = await lerArquivoTexto(fileInput.files[0]);
        }
        
        // 3. Obter a assinatura
        const signatureInput = document.getElementById('signatureInput').value.trim();
        if (!signatureInput) {
            mostrarErro('Por favor, insira a assinatura.');
            return;
        }
        
        // 4. Obter configurações
        const shaVersion = document.querySelector('input[name="verifyShaVersion"]:checked').value;
        const inputFormat = document.querySelector('input[name="verifyInputFormat"]:checked').value;
        
        // 5. Converter assinatura para bytes
        let signatureBytes;
        if (inputFormat === 'BASE64') {
            try {
                signatureBytes = forge.util.decode64(signatureInput);
            } catch (error) {
                mostrarErro('A assinatura não está em formato Base64 válido.');
                return;
            }
        } else { // HEX
            if (!/^[0-9A-Fa-f]+$/.test(signatureInput)) {
                mostrarErro('A assinatura não está em formato hexadecimal válido.');
                return;
            }
            signatureBytes = forge.util.hexToBytes(signatureInput);
        }
        
        // 6. Criar o hash do conteúdo
        let md;
        switch (shaVersion) {
            case '256':
                md = forge.md.sha256.create();
                break;
            case '384':
                md = forge.md.sha384.create();
                break;
            case '512':
                md = forge.md.sha512.create();
                break;
            default:
                mostrarErro('Versão de SHA inválida.');
                return;
        }
        
        md.update(content, 'utf8');
        
        // 7. Verificar a assinatura
        const isValid = publicKey.verify(md.digest().bytes(), signatureBytes);
        
        // 8. Exibir resultado
        const resultDiv = document.getElementById('verifyResult');
        const resultContainer = document.getElementById('verifyResultContainer');
        
        if (isValid) {
            resultDiv.textContent = '✅ Assinatura VÁLIDA';
            resultDiv.className = 'message message-success';
        } else {
            resultDiv.textContent = '❌ Assinatura INVÁLIDA';
            resultDiv.className = 'message message-error';
        }
        
        resultContainer.style.display = 'block';
        
        console.log(`Verificação concluída. Assinatura ${isValid ? 'VÁLIDA' : 'INVÁLIDA'}.`);
        
    } catch (error) {
        mostrarErro('Erro ao verificar assinatura: ' + error.message);
    }
}

/**
 * Faz download da assinatura gerada
 */
function baixarAssinatura() {
    if (!lastSignature) {
        mostrarErro('Nenhuma assinatura disponível.');
        return;
    }
    baixarArquivo(lastSignature, 'assinatura.txt');
}
