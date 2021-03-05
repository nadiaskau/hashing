let encryptionButton = document.getElementById("encrypt");
encryptionButton.addEventListener('click', function(){
    encryption();
});

let decryptionButton = document.getElementById("decrypt");
decryptionButton.addEventListener('click', function(){
    decryption();
});

function encryption(){
    let plaintext = document.getElementById("plaintext").value;
    let cipher = document.getElementById("cipherselect").value; 
    let ciphertext; 
    let output = document.getElementById("output");
    let key = document.getElementById("key").value; 

    switch (cipher) {
        case "MD5":
            ciphertext = CryptoJS.MD5(plaintext);
            output.innerHTML = "Hash: " + ciphertext; 
            break;
        case "SHA1":
            ciphertext = CryptoJS.SHA1(plaintext);
            output.innerHTML = "Hash: " + ciphertext; 
            break;
        case "SHA256":
            ciphertext = CryptoJS.SHA256(plaintext);
            output.innerHTML = "Hash: " + ciphertext; 
            break;
        case "AES":
            ciphertext = CryptoJS.AES.encrypt(plaintext, key);
            output.innerHTML = "Ciphertext: " + ciphertext; 
            break;
        case "DES":
            ciphertext = CryptoJS.DES.encrypt(plaintext, key);
            output.innerHTML = "Ciphertext: " + ciphertext; 
            break;
        case "rabbit":
            ciphertext = CryptoJS.Rabbit.encrypt(plaintext, key);
            output.innerHTML = "Ciphertext: " + ciphertext; 
            break;
        case "RC4":
            ciphertext = CryptoJS.RC4.encrypt(plaintext, key);
            output.innerHTML = "Ciphertext: " + ciphertext; 
            break;
    }
}

function decryption(){
    let ciphertext = document.getElementById("plaintext").value;
    let cipher = document.getElementById("cipherselect").value; 
    let plaintext; 
    let output = document.getElementById("output");
    let key = document.getElementById("key").value; 

    switch (cipher) {

        case "AES":
            plaintext = CryptoJS.AES.decrypt(ciphertext, key);
            output.innerHTML = "plaintext: " + plaintext.toString(CryptoJS.enc.Utf8); 
            break;
        case "DES":
            plaintext = CryptoJS.DES.decrypt(ciphertext, key);
            output.innerHTML = "plaintext: " + plaintext.toString(CryptoJS.enc.Utf8); 
            break;
        case "rabbit":
            plaintext = CryptoJS.Rabbit.decrypt(ciphertext, key);
            output.innerHTML = "plaintext: " + plaintext.toString(CryptoJS.enc.Utf8); 
            break;
        case "RC4":
            plaintext = CryptoJS.RC4.decrypt(ciphertext, key);
            output.innerHTML = "plaintext: " + plaintext.toString(CryptoJS.enc.Utf8); 
            break;
        default: 
            output.innerHTML = "NO! Hash cannot be reversed";
            break;
    }
}