#!/usr/bin/env python3
"""
Advanced Password Strength Checker
Features:
- Comprehensive strength analysis
- Common password detection
- Entropy calculation
- Detailed feedback and recommendations
- Batch password testing
- Security best practices
"""

import re
import math
import hashlib
import argparse
import sys
import json
from datetime import datetime
import string
from collections import Counter

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '123456', 'abcdef',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', 'abcdefghijk'
        ]
        
        # Character sets for entropy calculation
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': string.punctuation,
            'space': ' '
        }
    
    def load_common_passwords(self):
        """Load common passwords list"""
        # Top 100 most common passwords (sample)
        common_passwords = {
            '123456', 'password', '123456789', '12345678', '12345',
            '111111', '1234567', 'sunshine', 'qwerty', 'iloveyou',
            'princess', 'admin', 'welcome', '666666', 'abc123',
            'football', '123123', 'monkey', '654321', '!@#$%^&*',
            'charlie', 'aa123456', 'donald', 'password1', 'qwerty123',
            'login', 'master', 'hello', 'freedom', 'whatever',
            'jordan', 'batman', 'trustno1', '000000', 'starwars',
            'zaq12wsx', '123qwe', 'killer', 'superman', 'test',
            'azerty', '1234', 'shadow', 'dragon', 'michael',
            'mustang', 'letmein', 'baseball', '1q2w3e4r', 'access',
            'solo', 'loveme', 'flower', 'password123', 'admin123',
            'Password', '123456a', 'qwerty1', 'password1234', 'root',
            'toor', 'pass', '1234567890', 'qwertyuiop', 'asdfghjkl',
            'zxcvbnm', 'Temp123', 'guest', 'user', 'default',
            'changeme', 'newpassword', 'secret', 'mypassword'
        }
        return common_passwords
    
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        if not password:
            return 0
        
        # Determine character set size
        char_space = 0
        if re.search(r'[a-z]', password):
            char_space += 26
        if re.search(r'[A-Z]', password):
            char_space += 26
        if re.search(r'[0-9]', password):
            char_space += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            char_space += 32  # Special characters
        
        if char_space == 0:
            return 0
        
        # Calculate entropy: H = L * log2(N)
        # where L = length, N = character space
        entropy = len(password) * math.log2(char_space)
        
        # Apply penalties for patterns and repetition
        entropy = self.apply_entropy_penalties(password, entropy)
        
        return entropy
    
    def apply_entropy_penalties(self, password, entropy):
        """Apply penalties for patterns that reduce effective entropy"""
        penalty_factor = 1.0
        
        # Repetitive characters penalty
        char_counts = Counter(password)
        max_repetition = max(char_counts.values())
        if max_repetition > 1:
            penalty_factor *= (1.0 - (max_repetition - 1) * 0.1)
        
        # Sequential patterns penalty
        if self.has_sequential_pattern(password):
            penalty_factor *= 0.8
        
        # Dictionary words penalty
        if self.contains_dictionary_words(password):
            penalty_factor *= 0.7
        
        # Keyboard patterns penalty
        if self.has_keyboard_pattern(password):
            penalty_factor *= 0.6
        
        return entropy * max(penalty_factor, 0.1)
    
    def has_sequential_pattern(self, password):
        """Check for sequential patterns (abc, 123, etc.)"""
        password_lower = password.lower()
        
        # Check for ascending sequences
        for i in range(len(password_lower) - 2):
            if (ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and
                ord(password_lower[i+2]) == ord(password_lower[i]) + 2):
                return True
        
        # Check for descending sequences
        for i in range(len(password_lower) - 2):
            if (ord(password_lower[i+1]) == ord(password_lower[i]) - 1 and
                ord(password_lower[i+2]) == ord(password_lower[i]) - 2):
                return True
        
        return False
    
    def has_keyboard_pattern(self, password):
        """Check for keyboard patterns"""
        password_lower = password.lower()
        
        for pattern in self.keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    def contains_dictionary_words(self, password):
        """Check for common dictionary words"""
        password_lower = password.lower()
        
        # Check for common words (simplified check)
        common_words = [
            'password', 'admin', 'user', 'login', 'welcome',
            'hello', 'world', 'test', 'default', 'secret',
            'love', 'money', 'family', 'friends', 'computer'
        ]
        
        for word in common_words:
            if word in password_lower:
                return True
        
        return False
    
    def check_common_password(self, password):
        """Check if password is in common passwords list"""
        return password.lower() in {p.lower() for p in self.common_passwords}
    
    def analyze_composition(self, password):
        """Analyze password character composition"""
        composition = {
            'length': len(password),
            'lowercase': len(re.findall(r'[a-z]', password)),
            'uppercase': len(re.findall(r'[A-Z]', password)),
            'digits': len(re.findall(r'[0-9]', password)),
            'symbols': len(re.findall(r'[^a-zA-Z0-9]', password)),
            'spaces': password.count(' ')
        }
        
        composition['char_variety'] = sum(1 for count in 
            [composition['lowercase'], composition['uppercase'], 
             composition['digits'], composition['symbols']] if count > 0)
        
        return composition
    
    def calculate_crack_time(self, entropy):
        """Estimate time to crack password"""
        if entropy <= 0:
            return "Instantly"
        
        # Assume 10^9 guesses per second (modern GPU)
        guesses_per_second = 10**9
        total_combinations = 2**entropy
        
        # Average time is half the total combinations
        seconds = (total_combinations / 2) / guesses_per_second
        
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000 * 100:
            return f"{seconds/31536000:.1f} years"
        elif seconds < 31536000 * 1000:
            return f"{seconds/(31536000*100):.1f} centuries"
        else:
            return "Millions of years"
    
    def get_strength_level(self, entropy, composition):
        """Determine password strength level"""
        if entropy < 25:
            return "Very Weak"
        elif entropy < 40:
            return "Weak"
        elif entropy < 55:
            return "Fair"
        elif entropy < 70:
            return "Good"
        elif entropy < 85:
            return "Strong"
        else:
            return "Very Strong"
    
    def generate_recommendations(self, password, composition, entropy):
        """Generate specific recommendations for password improvement"""
        recommendations = []
        
        # Length recommendations
        if composition['length'] < 8:
            recommendations.append("❌ Increase length to at least 8 characters")
        elif composition['length'] < 12:
            recommendations.append("⚠️  Consider increasing length to 12+ characters for better security")
        else:
            recommendations.append("✅ Good length")
        
        # Character variety recommendations
        if composition['lowercase'] == 0:
            recommendations.append("❌ Add lowercase letters (a-z)")
        else:
            recommendations.append("✅ Contains lowercase letters")
        
        if composition['uppercase'] == 0:
            recommendations.append("❌ Add uppercase letters (A-Z)")
        else:
            recommendations.append("✅ Contains uppercase letters")
        
        if composition['digits'] == 0:
            recommendations.append("❌ Add numbers (0-9)")
        else:
            recommendations.append("✅ Contains numbers")
        
        if composition['symbols'] == 0:
            recommendations.append("❌ Add special characters (!@#$%^&*)")
        else:
            recommendations.append("✅ Contains special characters")
        
        # Pattern checks
        if self.has_sequential_pattern(password):
            recommendations.append("❌ Avoid sequential patterns (abc, 123)")
        
        if self.has_keyboard_pattern(password):
            recommendations.append("❌ Avoid keyboard patterns (qwerty, asdf)")
        
        if self.contains_dictionary_words(password):
            recommendations.append("❌ Avoid common dictionary words")
        
        if self.check_common_password(password):
            recommendations.append("❌ This is a commonly used password - change immediately!")
        
        # Repetition check
        char_counts = Counter(password)
        max_repetition = max(char_counts.values()) if char_counts else 0
        if max_repetition > 2:
            recommendations.append("❌ Reduce character repetition")
        
        return recommendations
    
    def check_password(self, password):
        """Main function to check password strength"""
        if not password:
            return {
                'error': 'Password cannot be empty'
            }
        
        # Calculate metrics
        entropy = self.calculate_entropy(password)
        composition = self.analyze_composition(password)
        strength_level = self.get_strength_level(entropy, composition)
        crack_time = self.calculate_crack_time(entropy)
        recommendations = self.generate_recommendations(password, composition, entropy)
        
        # Additional checks
        is_common = self.check_common_password(password)
        has_patterns = (self.has_sequential_pattern(password) or 
                       self.has_keyboard_pattern(password) or
                       self.contains_dictionary_words(password))
        
        return {
            'password_length': len(password),
            'entropy': round(entropy, 2),
            'strength_level': strength_level,
            'crack_time': crack_time,
            'composition': composition,
            'is_common_password': is_common,
            'has_patterns': has_patterns,
            'recommendations': recommendations,
            'score': min(100, int((entropy / 85) * 100))  # Score out of 100
        }
    
    def generate_password_report(self, password):
        """Generate a detailed password analysis report"""
        result = self.check_password(password)
        
        if 'error' in result:
            return result['error']
        
        report = f"""
🔐 PASSWORD STRENGTH ANALYSIS REPORT
{'='*50}

Password Length: {result['password_length']} characters
Entropy: {result['entropy']} bits
Strength Level: {result['strength_level']}
Security Score: {result['score']}/100
Estimated Crack Time: {result['crack_time']}

📊 CHARACTER COMPOSITION:
• Lowercase letters: {result['composition']['lowercase']}
• Uppercase letters: {result['composition']['uppercase']}
• Numbers: {result['composition']['digits']}
• Special characters: {result['composition']['symbols']}
• Character variety: {result['composition']['char_variety']}/4

⚠️  SECURITY ISSUES:
• Common password: {'Yes' if result['is_common_password'] else 'No'}
• Contains patterns: {'Yes' if result['has_patterns'] else 'No'}

💡 RECOMMENDATIONS:
"""
        
        for rec in result['recommendations']:
            report += f"   {rec}\n"
        
        report += f"""
🛡️  SECURITY GUIDELINES:
• Use at least 12 characters
• Mix uppercase, lowercase, numbers, and symbols
• Avoid dictionary words and personal information
• Don't reuse passwords across accounts
• Consider using a password manager
• Enable two-factor authentication where possible

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return report
    
    def batch_check(self, passwords):
        """Check multiple passwords and return summary"""
        results = []
        
        for i, password in enumerate(passwords):
            result = self.check_password(password)
            result['index'] = i + 1
            results.append(result)
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Strength Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_checker.py -p "MySecureP@ssw0rd123"
  python password_checker.py -f passwords.txt
  python password_checker.py -i  # Interactive mode
  python password_checker.py -p "password123" --json
        """
    )
    
    parser.add_argument('-p', '--password', help='Password to check')
    parser.add_argument('-f', '--file', help='File containing passwords to check (one per line)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    checker = PasswordStrengthChecker()
    
    if args.interactive:
        print("🔐 Interactive Password Strength Checker")
        print("Enter passwords to check (or 'quit' to exit):")
        
        while True:
            try:
                password = input("\nEnter password: ")
                if password.lower() == 'quit':
                    break
                
                if args.json:
                    result = checker.check_password(password)
                    print(json.dumps(result, indent=2))
                else:
                    report = checker.generate_password_report(password)
                    print(report)
                    
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
    
    elif args.password:
        if args.json:
            result = checker.check_password(args.password)
            output = json.dumps(result, indent=2)
        else:
            output = checker.generate_password_report(args.password)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results saved to {args.output}")
        else:
            print(output)
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            results = checker.batch_check(passwords)
            
            if args.json:
                output = json.dumps(results, indent=2)
            else:
                output = "🔐 BATCH PASSWORD ANALYSIS\n" + "="*50 + "\n\n"
                for result in results:
                    if 'error' not in result:
                        output += f"Password {result['index']}: {result['strength_level']} "
                        output += f"({result['score']}/100, {result['entropy']} bits)\n"
                    else:
                        output += f"Password {result['index']}: Error - {result['error']}\n"
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(output)
                print(f"Results saved to {args.output}")
            else:
                print(output)
                
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()