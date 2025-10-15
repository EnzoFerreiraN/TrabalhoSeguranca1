// ========================================
// AES-CRYPTO.JS - Cifragem e Decifragem AES
// ========================================

// Variáveis para armazenar os últimos resultados
let lastAesKey = null;
let lastAesIv = null;
let lastAesCiphertext = null;
let lastAesDecrypted = null;

/**
 * Alterna entre as abas de entrada AES (Texto/Arquivo) para cifragem
 */
function alternarAbaAes(tab) {
    document.getElementById('tabAesText').classList.remove('active');
    document.getElementById('tabAesFile').classList.remove('active');
    document.getElementById('contentAesText').classList.remove('active');
    document.getElementById('contentAesFile').classList.remove('active');
    
    document.getElementById('tabAes' + tab).classList.add('active');
    document.getElementById('contentAes' + tab).classList.add('active');
}

/**
 * Alterna entre as abas de entrada AES (Texto/Arquivo) para decifragem
 */
function alternarAbaAesDec(tab) {
    document.getElementById('tabAesDecText').classList.remove('active');
    document.getElementById('tabAesDecFile').classList.remove('active');
    document.getElementById('contentAesDecText').classList.remove('active');
    document.getElementById('contentAesDecFile').classList.remove('active');
    
    document.getElementById('tabAesDec' + tab).classList.add('active');
    document.getElementById('contentAesDec' + tab).classList.add('active');
}

// Funções de processamento de chave removidas - agora usa apenas geração aleatória

/**
 * Criptografa dados usando AES
 */
async function criptografarAES() {
    console.log('Iniciando cifragem AES...');
    
    try {
        // 1. Obter o texto ou arquivo para criptografar
        let plaintext;
        if (document.getElementById('tabAesText').classList.contains('active')) {
            plaintext = document.getElementById('aesTextInput').value;
            if (!plaintext.trim()) {
                mostrarErro('Por favor, digite um texto para criptografar.');
                return;
            }
        } else {
            const fileInput = document.getElementById('aesFileInput');
            if (!fileInput.files.length) {
                mostrarErro('Por favor, selecione um arquivo para criptografar.');
                return;
            }
            plaintext = await lerArquivoTexto(fileInput.files[0]);
        }
        
        // 2. Obter configurações
        const keySize = parseInt(document.querySelector('input[name="aesKeySize"]:checked').value);
        const mode = document.querySelector('input[name="aesMode"]:checked').value;
        const outputFormat = document.querySelector('input[name="aesOutputFormat"]:checked').value;
        
        console.log(`📋 Configurações AES: ${keySize} bits, Modo ${mode}, Saída ${outputFormat}`);
        
        // 3. Gerar chave AES aleatória (SEMPRE)
        const keyBytes = keySize / 8;
        const aesKey = forge.random.getBytesSync(keyBytes);
        console.log(`✅ Chave AES de ${keySize} bits gerada aleatoriamente (${aesKey.length} bytes = ${aesKey.length * 8} bits).`);
        
        // VALIDAÇÃO: Garantir que a chave tem o tamanho correto
        if (aesKey.length !== keyBytes) {
            console.error(`❌ ERRO CRÍTICO: Chave gerada tem ${aesKey.length} bytes, mas deveria ter ${keyBytes} bytes!`);
            mostrarErro(`Erro ao gerar chave: tamanho incorreto (${aesKey.length} bytes em vez de ${keyBytes} bytes).`);
            return;
        }
        
        // 4. Gerar IV para modo CBC
        let iv = null;
        if (mode === 'CBC') {
            // Gerar IV aleatório (sempre 16 bytes = 128 bits para AES)
            iv = forge.random.getBytesSync(16);
            console.log('✅ IV de 128 bits gerado aleatoriamente para CBC.');
        }
        
        // 5. Configurar e executar a cifra AES
        // PADDING: node-forge usa PKCS#7 por padrão (compatível com OpenSSL e CyberChef)
        // PKCS#7 adiciona bytes de padding automaticamente para completar blocos de 16 bytes
        let cipher;
        if (mode === 'CBC') {
            cipher = forge.cipher.createCipher('AES-CBC', aesKey);
            cipher.start({iv: iv});
        } else { // ECB
            cipher = forge.cipher.createCipher('AES-ECB', aesKey);
            cipher.start();
        }
        
        cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
        // finish() aplica o padding PKCS#7 automaticamente
        cipher.finish();
        
        const ciphertext = cipher.output.getBytes();
        
        // 6. Formatar resultados para exibição (sempre Binary String → Base64/HEX)
        let formattedKey, formattedIv, formattedCiphertext;
        
        console.log(`📤 Formatando resultados para saída (${outputFormat})...`);
        console.log(`   Chave original: ${aesKey.length} bytes (${aesKey.length * 8} bits)`);
        console.log(`   Texto cifrado: ${ciphertext.length} bytes`);
        if (mode === 'CBC') {
            console.log(`   IV: ${iv.length} bytes (${iv.length * 8} bits)`);
        }
        
        if (outputFormat === 'BASE64') {
            // Binary String → Base64 (melhor para copiar/colar)
            formattedKey = forge.util.encode64(aesKey);
            formattedCiphertext = forge.util.encode64(ciphertext);
            formattedIv = mode === 'CBC' ? forge.util.encode64(iv) : null;
            
            console.log(`✅ Resultados formatados em Base64:`);
            console.log(`   Chave Base64: ${formattedKey.length} caracteres (${aesKey.length} bytes originais = ${aesKey.length * 8} bits)`);
            console.log(`   Texto cifrado Base64: ${formattedCiphertext.length} caracteres`);
            if (mode === 'CBC') {
                console.log(`   IV Base64: ${formattedIv.length} caracteres (${iv.length} bytes originais = ${iv.length * 8} bits)`);
            }
        } else { // HEX
            // Binary String → Hexadecimal
            formattedKey = forge.util.bytesToHex(aesKey).toUpperCase();
            formattedCiphertext = forge.util.bytesToHex(ciphertext).toUpperCase();
            formattedIv = mode === 'CBC' ? forge.util.bytesToHex(iv).toUpperCase() : null;
            
            console.log(`✅ Resultados formatados em HEX:`);
            console.log(`   Chave HEX: ${formattedKey.length} caracteres (${aesKey.length} bytes originais = ${aesKey.length * 8} bits)`);
            console.log(`   Texto cifrado HEX: ${formattedCiphertext.length} caracteres`);
            if (mode === 'CBC') {
                console.log(`   IV HEX: ${formattedIv.length} caracteres (${iv.length} bytes originais = ${iv.length * 8} bits)`);
            }
        }
        
        // 7. Armazenar e exibir resultados
        lastAesKey = formattedKey;
        lastAesCiphertext = formattedCiphertext;
        lastAesIv = formattedIv;
        
        document.getElementById('aesKeyOutput').textContent = formattedKey;
        document.getElementById('aesCipherOutput').textContent = formattedCiphertext;
        
        if (mode === 'CBC') {
            document.getElementById('aesIvOutput').textContent = formattedIv;
            document.getElementById('aesIvContainer').style.display = 'block';
        } else {
            document.getElementById('aesIvContainer').style.display = 'none';
        }
        
        document.getElementById('aesResultContainer').style.display = 'block';
        mostrarSucesso('Cifragem AES concluída com sucesso!');
        
    } catch (error) {
        mostrarErro('Erro na cifragem AES: ' + error.message);
    }
}

/**
 * Descriptografa dados usando AES
 */
async function descriptografarAES() {
    console.log('Iniciando decifragem AES...');
    
    try {
        // 1. Obter texto cifrado
        let ciphertextInput;
        if (document.getElementById('tabAesDecText').classList.contains('active')) {
            ciphertextInput = document.getElementById('aesDecTextInput').value.trim();
            if (!ciphertextInput) {
                mostrarErro('Por favor, insira o texto cifrado.');
                return;
            }
        } else {
            const fileInput = document.getElementById('aesDecFileInput');
            if (!fileInput.files.length) {
                mostrarErro('Por favor, selecione um arquivo com o texto cifrado.');
                return;
            }
            ciphertextInput = await lerArquivoTexto(fileInput.files[0]);
        }
        
        // 2. Obter configurações
        const keySize = parseInt(document.querySelector('input[name="aesDecKeySize"]:checked').value);
        const mode = document.querySelector('input[name="aesDecMode"]:checked').value;
        const inputFormat = document.querySelector('input[name="aesDecInputFormat"]:checked').value;
        
        console.log(`📋 Configurações decifragem: ${keySize} bits, Modo ${mode}, Entrada ${inputFormat}`);
        
        // 3. Obter a chave AES
        const keyInput = document.getElementById('aesKeyInput').value.trim();
        if (!keyInput) {
            mostrarErro('Por favor, insira a chave AES.');
            return;
        }
        
        // Converter chave do formato de entrada
        const keyBytes = keySize / 8;
        let aesKey;
        
        if (inputFormat === 'BASE64') {
            try {
                aesKey = forge.util.decode64(keyInput);
                console.log('✅ Chave AES decodificada de Base64.');
            } catch (error) {
                mostrarErro('A chave AES não está em formato Base64 válido.');
                return;
            }
        } else { // HEX
            if (!/^[0-9A-Fa-f\s]+$/.test(keyInput)) {
                mostrarErro('A chave AES não está em formato hexadecimal válido. Use apenas 0-9 e A-F.');
                return;
            }
            aesKey = forge.util.hexToBytes(keyInput.replace(/\s+/g, ''));
            console.log('✅ Chave AES convertida de HEX.');
        }
        
        // Validar tamanho da chave
        if (aesKey.length !== keyBytes) {
            mostrarErro(`A chave AES tem ${aesKey.length * 8} bits, mas o tamanho selecionado é ${keySize} bits.\n\nVerifique se copiou a chave correta.`);
            return;
        }
        
        // 4. Obter IV (se modo CBC)
        let iv = null;
        if (mode === 'CBC') {
            const ivInput = document.getElementById('aesIvInput').value.trim();
            
            if (!ivInput) {
                mostrarErro('Para o modo CBC, é necessário fornecer o IV.');
                return;
            }
            
            // Converter IV do formato de entrada
            if (inputFormat === 'BASE64') {
                try {
                    iv = forge.util.decode64(ivInput);
                    console.log('✅ IV decodificado de Base64.');
                } catch (error) {
                    mostrarErro('O IV não está em formato Base64 válido.');
                    return;
                }
            } else { // HEX
                if (!/^[0-9A-Fa-f\s]+$/.test(ivInput)) {
                    mostrarErro('O IV não está em formato hexadecimal válido. Use apenas 0-9 e A-F.');
                    return;
                }
                iv = forge.util.hexToBytes(ivInput.replace(/\s+/g, ''));
                console.log('✅ IV convertido de HEX.');
            }
            
            // Validar tamanho do IV (deve ser sempre 16 bytes)
            if (iv.length !== 16) {
                mostrarErro(`O IV deve ter 16 bytes (128 bits), mas tem ${iv.length} bytes.`);
                return;
            }
        }
        
        // 5. Converter texto cifrado para bytes
        let ciphertextBytes;
        ciphertextInput = ciphertextInput.trim().replace(/\s+/g, ''); // Remove espaços
        
        if (inputFormat === 'BASE64') {
            try {
                ciphertextBytes = forge.util.decode64(ciphertextInput);
                console.log('Texto cifrado decodificado de Base64.');
            } catch (error) {
                mostrarErro('O texto cifrado não está em formato Base64 válido. Verifique se copiou corretamente.');
                return;
            }
        } else { // HEX
            if (!/^[0-9A-Fa-f]+$/.test(ciphertextInput)) {
                mostrarErro('O texto cifrado não está em formato hexadecimal válido. Use apenas 0-9 e A-F.');
                return;
            }
            ciphertextBytes = forge.util.hexToBytes(ciphertextInput);
            console.log('Texto cifrado convertido de HEX.');
        }
        
        // Validar que o texto cifrado tem tamanho adequado (múltiplo de 16 bytes para AES)
        if (ciphertextBytes.length === 0) {
            mostrarErro('O texto cifrado está vazio.');
            return;
        }
        
        if (ciphertextBytes.length % 16 !== 0) {
            mostrarErro(`O texto cifrado deve ter um tamanho múltiplo de 16 bytes (AES block size). Tamanho atual: ${ciphertextBytes.length} bytes.`);
            return;
        }
        
        // 6. Configurar e executar a decifra AES
        // PADDING: node-forge remove PKCS#7 automaticamente durante decifragem
        // Valida e remove os bytes de padding conforme padrão PKCS#7
        let decipher;
        if (mode === 'CBC') {
            decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
            decipher.start({iv: iv});
        } else { // ECB
            decipher = forge.cipher.createDecipher('AES-ECB', aesKey);
            decipher.start();
        }
        
        decipher.update(forge.util.createBuffer(ciphertextBytes, 'raw'));
        // finish() valida e remove o padding PKCS#7 automaticamente
        // Retorna false se o padding for inválido (texto cifrado corrompido/chave errada)
        const result = decipher.finish();
        
        if (!result) {
            mostrarErro('Falha na decifragem. Verifique se:\n' +
                       '• A chave está correta\n' +
                       '• O IV está correto (para CBC)\n' +
                       '• O formato do texto cifrado está correto\n' +
                       '• Os parâmetros (modo, tamanho) são os mesmos da cifragem');
            return;
        }
        
        // 7. Obter e exibir texto decifrado
        const decrypted = decipher.output.toString('utf8');
        
        // Validar que o texto decifrado tem conteúdo
        if (!decrypted) {
            mostrarErro('O texto decifrado está vazio. Verifique os parâmetros.');
            return;
        }
        
        lastAesDecrypted = decrypted;
        
        document.getElementById('aesDecOutput').textContent = decrypted;
        document.getElementById('aesDecResultContainer').style.display = 'block';
        
        console.log('Decifragem AES concluída com sucesso!');
        mostrarSucesso('Decifragem AES concluída com sucesso!');
        
    } catch (error) {
        mostrarErro('Erro na decifragem AES: ' + error.message);
    }
}

/**
 * Baixa a chave AES gerada
 */
function baixarAesOutput(elementId, defaultFilename) {
    const content = document.getElementById(elementId).textContent;
    if (!content) {
        mostrarErro('Nenhum conteúdo disponível para download.');
        return;
    }
    baixarArquivo(content, defaultFilename);
}

/**
 * Baixa o texto decifrado
 */
function baixarAesDecrypted() {
    if (!lastAesDecrypted) {
        mostrarErro('Nenhum conteúdo AES decifrado disponível.');
        return;
    }
    baixarArquivo(lastAesDecrypted, 'texto_decifrado_aes.txt');
}
