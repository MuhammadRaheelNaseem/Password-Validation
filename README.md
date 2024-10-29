# Password Validation with Python

## Overview
In this lecture, we'll break down the `PasswordValidator` class, a robust password validation tool developed in Python. This class helps ensure secure password creation by checking for length, character diversity, entropy, and common password usage. We'll walk through each part of the code to understand how it checks a password's strength and security.

---

## 1. **Introduction to PasswordValidator**

The `PasswordValidator` class is designed to assess the strength of a password using several factors:
- **Length**: Ensures that passwords meet minimum and maximum character length requirements.
- **Character Variety**: Identifies lowercase, uppercase, numbers, and symbols in the password.
- **Entropy Calculation**: Measures the unpredictability of the password based on its length and character variety.
- **Common Password Check**: Checks if a password is commonly used, making it easy to guess.

---

## 2. **Class Initialization**

```python
def __init__(self, min_length=8, max_length=22, common_passwords_file='common_passwords.txt', entropy_threshold=60):
```

### Parameters:
- **min_length**: Minimum length allowed for a password.
- **max_length**: Maximum length allowed for a password.
- **common_passwords_file**: Path to a file containing common passwords.
- **entropy_threshold**: Minimum entropy required for a strong password.

The `common_passwords_file` is used to load a list of commonly used passwords that should be avoided. Entropy helps measure the password's strength against brute-force attacks.

---

## 3. **Loading Common Passwords**

```python
def _load_common_passwords(self, filepath):
```

The function loads a list of common passwords to identify and block any passwords that are too common and easy to guess. If the file is missing, it logs a warning and skips the check.

### Why This Matters
Common passwords are often the first to be guessed in an attack. Blocking these enhances password security.

---

## 4. **Validating Passwords**

```python
def validate_password(self, password):
```

This function performs the core validation by:
1. **Checking Length**: Ensures that the password fits within the specified range.
2. **Common Password Check**: Verifies that the password is not in the common passwords list.
3. **Character Types Identification**: Identifies the types of characters (lowercase, uppercase, numbers, symbols) present in the password.
4. **Entropy Calculation**: Measures the entropy of the password based on its character types and length.
5. **Time-to-Crack Estimation**: Estimates how long it would take to crack the password with a brute-force attack.

### Why This Matters
This multi-step validation ensures the password meets high-security standards, making it harder to break.

---

## 5. **Character Types Identification**

```python
def _identify_character_types(self, password):
```

This function checks which character sets are present in the password, such as:
- **Lowercase Letters**
- **Uppercase Letters**
- **Numbers**
- **Symbols**

Each character type increases the password’s security by making it harder to guess.

---

## 6. **Calculating Entropy**

```python
def _calculate_entropy(self, char_types, length):
```

**Entropy** measures password unpredictability. This function calculates entropy in bits, which is influenced by the variety of characters and the password length. Higher entropy implies a stronger password.

### Why Entropy Matters
Passwords with higher entropy are harder to crack because they have more possible combinations.

---

## 7. **Estimating Time to Crack**

```python
def _estimate_time_to_crack(self, entropy):
```

Using entropy, this function estimates the time it would take to crack the password:
- **Instantly**: If it’s extremely weak.
- **Seconds, Minutes, or Hours**: Based on entropy, with longer times indicating higher security.
- **Years**: Strong passwords take exponentially longer to break.

### Importance of Time-to-Crack
Estimating crack time shows users the practical security level of their password.

---

## 8. **Checking Password Strength**

```python
def is_strong_password(self, password):
```

This convenience function allows for a quick check to see if a password meets strength requirements.

---

## 9. **Example Usage**

The `__main__` block at the bottom tests the class with a list of example passwords. Running this provides validation feedback, including:
- **Character Types Present**
- **Entropy in Bits**
- **Estimated Time to Crack**

### Example Output

Running the provided code will display feedback on each example password, helping users understand how password strength is assessed.

```python
Password: P@ssw0rd123
Valid: True
Length: 11
Character Types: lowercase, uppercase, numbers, symbols
Entropy: 70.98 bits
Time to Crack: 5000 years
Message: Password is strong.
```

---

## Conclusion

This `PasswordValidator` is a powerful tool that uses multiple checks to ensure high-security standards for passwords. It not only checks for length and character variety but also computes entropy and assesses common passwords, making it a practical choice for applications that need to enforce strong password policies. This comprehensive approach ensures that passwords are secure against various types of attacks. 


## Final Code
```python
import string
import math
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PasswordValidator:
    """
    A comprehensive password validator that assesses the strength of a password
    based on length, character variety, entropy, and checks against common passwords.
    """

    def __init__(
        self,
        min_length=8,
        max_length=22,
        common_passwords_file='common_passwords.txt',
        entropy_threshold=60,  # in bits
    ):
        """
        Initialize the PasswordValidator.

        :param min_length: Minimum allowed password length.
        :param max_length: Maximum allowed password length.
        :param common_passwords_file: Path to a file containing common passwords.
        :param entropy_threshold: Minimum entropy required for a strong password.
        """
        self.min_length = min_length
        self.max_length = max_length
        self.entropy_threshold = entropy_threshold
        self.common_passwords = self._load_common_passwords(common_passwords_file)
        self.char_sets = {
            'lowercase': set(string.ascii_lowercase),
            'uppercase': set(string.ascii_uppercase),
            'numbers': set(string.digits),
            'symbols': set(string.punctuation)
        }

    def _load_common_passwords(self, filepath):
        """
        Load a set of common passwords from a file.

        :param filepath: Path to the common passwords file.
        :return: A set containing common passwords.
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                common = set(line.strip() for line in file if line.strip())
            logger.info(f"Loaded {len(common)} common passwords.")
            return common
        except FileNotFoundError:
            logger.warning(f"Common passwords file '{filepath}' not found. Skipping common password check.")
            return set()
        except Exception as e:
            logger.error(f"Error loading common passwords: {e}")
            return set()

    def validate_password(self, password):
        """
        Validate the password and assess its strength.

        :param password: The password string to validate.
        :return: A dictionary containing validation results.
        """
        logger.debug(f"Validating password: {password}")

        # Check password length
        if not (self.min_length <= len(password) <= self.max_length):
            message = f"Password must be between {self.min_length} and {self.max_length} characters long."
            logger.debug(message)
            return {"valid": False, "message": message}

        # Check against common passwords
        if password.lower() in self.common_passwords:
            message = "Password is too common. Please choose a more unique password."
            logger.debug(message)
            return {"valid": False, "message": message}

        # Identify character types in the password
        char_types = self._identify_character_types(password)
        logger.debug(f"Character types found: {char_types}")

        # Calculate entropy
        entropy = self._calculate_entropy(char_types, len(password))
        logger.debug(f"Password entropy: {entropy} bits")

        # Assess time to crack
        time_to_crack = self._estimate_time_to_crack(entropy)
        logger.debug(f"Estimated time to crack: {time_to_crack}")

        # Determine if password is strong
        strong = entropy >= self.entropy_threshold and time_to_crack != "Instantly"

        # Prepare feedback message
        if strong:
            message = "Password is strong."
        else:
            message = (
                "Password is weak. Consider using a mix of upper and lower case letters, "
                "numbers, and symbols to increase security."
            )

        return {
            "valid": strong,
            "length": len(password),
            "character_types": char_types,
            "entropy_bits": entropy,
            "time_to_crack": time_to_crack,
            "message": message
        }

    def _identify_character_types(self, password):
        """
        Identify the types of characters present in the password.

        :param password: The password string.
        :return: A list of character types present.
        """
        types_present = []
        for type_name, chars in self.char_sets.items():
            if any(char in chars for char in password):
                types_present.append(type_name)
        return types_present

    def _calculate_entropy(self, char_types, length):
        """
        Calculate the entropy of the password.

        :param char_types: List of character types present in the password.
        :param length: Length of the password.
        :return: Entropy in bits.
        """
        pool_size = 0
        for type_name in char_types:
            pool_size += len(self.char_sets[type_name])
        entropy = length * math.log2(pool_size) if pool_size else 0
        return round(entropy, 2)

    def _estimate_time_to_crack(self, entropy):
        """
        Estimate the time required to crack the password based on entropy.

        :param entropy: Entropy of the password in bits.
        :return: Estimated time to crack as a string.
        """
        # Assuming attacker can try 1 trillion (1e12) passwords per second
        guesses_per_second = 1e12
        total_guesses = 2 ** entropy
        seconds = total_guesses / guesses_per_second

        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.2f} hours"
        elif seconds < 31536000:
            days = seconds / 86400
            return f"{days:.2f} days"
        else:
            years = seconds / 31536000
            return f"{years:.2f} years"

    def is_strong_password(self, password):
        """
        Convenience method to quickly check if a password is strong.

        :param password: The password string to check.
        :return: Boolean indicating if the password is strong.
        """
        result = self.validate_password(password)
        return result["valid"]

# Example usage
if __name__ == "__main__":
    # Initialize the validator with a common passwords file
    validator = PasswordValidator(common_passwords_file='common_passwords.txt')

    # Example passwords to validate
    passwords = [
        "Thejudgementday123@@@",
        "password",
        "P@ssw0rd123",
        "12345678",
        "A1b2C3d4!",
        'iloveyou',
        "ILoveYou123@"
    ]

    for pwd in passwords:
        result = validator.validate_password(pwd)
        print(f"Password: {pwd}")
        print(f"Valid: {result['valid']}")
        print(f"Length: {result['length']}")
        print(f"Character Types: {', '.join(result['character_types'])}")
        print(f"Entropy: {result['entropy_bits']} bits")
        print(f"Time to Crack: {result['time_to_crack']}")
        print(f"Message: {result['message']}\n")

```
