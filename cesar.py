def cifrar_cesar(texto, corrimiento):
    resultado = ""

    for char in texto:
        # Verificar si el carácter es una letra mayúscula
        if char.isupper():
            # Cifrar el carácter y agregarlo al resultado
            resultado += chr((ord(char) + corrimiento - 65) % 26 + 65)
        # Verificar si el carácter es una letra minúscula
        elif char.islower():
            # Cifrar el carácter y agregarlo al resultado
            resultado += chr((ord(char) + corrimiento - 97) % 26 + 97)
        else:
            # No cifrar caracteres que no sean letras
            resultado += char

    return resultado

# Ejemplo de uso
texto = input("Ingresa el texto a cifrar: ")
corrimiento = int(input("Ingresa el número de corrimiento: "))

texto_cifrado = cifrar_cesar(texto, corrimiento)
print(f"Texto cifrado: {texto_cifrado}")
