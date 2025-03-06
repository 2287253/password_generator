import streamlit as st
import random
import string
import pyperclip
import re
from typing import List, Optional

# Initialize session state for storing the generated password
if 'generated_password' not in st.session_state:
    st.session_state.generated_password = None

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
    def generate_password(self, length: int = 12, 
                         use_uppercase: bool = True,
                         use_digits: bool = True,
                         use_special: bool = True) -> str:
        """
        Generate a random password with specified criteria
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        # Initialize password with at least one lowercase letter
        password = [random.choice(self.lowercase)]
        
        # Add required character types
        if use_uppercase:
            password.append(random.choice(self.uppercase))
        if use_digits:
            password.append(random.choice(self.digits))
        if use_special:
            password.append(random.choice(self.special_chars))
            
        # Fill the rest randomly
        all_chars = self.lowercase
        if use_uppercase:
            all_chars += self.uppercase
        if use_digits:
            all_chars += self.digits
        if use_special:
            all_chars += self.special_chars
            
        while len(password) < length:
            password.append(random.choice(all_chars))
            
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password)
    
    def check_strength(self, password: str) -> dict:
        """
        Check password strength and return a dictionary with strength metrics
        """
        strength = {
            'length': len(password),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:,.<>?]', password)),
            'score': 0
        }
        
        # Calculate strength score
        if strength['length'] >= 8:
            strength['score'] += 1
        if strength['has_uppercase']:
            strength['score'] += 1
        if strength['has_lowercase']:
            strength['score'] += 1
        if strength['has_digits']:
            strength['score'] += 1
        if strength['has_special']:
            strength['score'] += 1
            
        return strength

def main():
    st.set_page_config(
        page_title="Password Generator",
        page_icon="🔒",
        layout="centered"
    )
    
    st.title("🔒 Password Generator")
    st.markdown("Generate strong passwords and check password strength with ease!")
    
    # Initialize the password generator
    generator = PasswordGenerator()
    
    # Create tabs for different functionalities
    tab1, tab2 = st.tabs(["Generate Password", "Check Strength"])
    
    with tab1:
        st.header("Generate New Password")
        
        # Password generation options
        col1, col2 = st.columns(2)
        
        with col1:
            length = st.slider("Password Length", min_value=8, max_value=32, value=12)
            use_uppercase = st.checkbox("Include Uppercase Letters", value=True)
            use_digits = st.checkbox("Include Numbers", value=True)
            use_special = st.checkbox("Include Special Characters", value=True)
        
        # Generate password button
        if st.button("Generate Password"):
            try:
                password = generator.generate_password(
                    length=length,
                    use_uppercase=use_uppercase,
                    use_digits=use_digits,
                    use_special=use_special
                )
                
                # Store the generated password in session state
                st.session_state.generated_password = password
                
                # Display the generated password
                st.success("Password Generated Successfully!")
                st.code(password, language="text")
                
            except ValueError as e:
                st.error(f"Error: {e}")
        
        # Copy to clipboard button (always visible but disabled if no password)
        if st.button("Copy to Clipboard", disabled=st.session_state.generated_password is None):
            if st.session_state.generated_password:
                pyperclip.copy(st.session_state.generated_password)
                st.success("Password copied to clipboard!")
    
    with tab2:
        st.header("Check Password Strength")
        
        # Password strength checker
        password_to_check = st.text_input("Enter password to check strength:", type="password")
        
        if st.button("Check Strength"):
            if password_to_check:
                strength = generator.check_strength(password_to_check)
                
                # Display strength metrics
                st.subheader("Password Strength Analysis")
                
                # Create columns for metrics
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("Length", f"{strength['length']} characters")
                    st.metric("Contains Uppercase", "Yes" if strength['has_uppercase'] else "No")
                
                with col2:
                    st.metric("Contains Lowercase", "Yes" if strength['has_lowercase'] else "No")
                    st.metric("Contains Numbers", "Yes" if strength['has_digits'] else "No")
                
                # Strength score with progress bar
                st.subheader("Overall Strength Score")
                st.progress(strength['score'] / 5)
                st.markdown(f"**Score: {strength['score']}/5**")
                
                # Strength recommendations
                if strength['score'] < 3:
                    st.warning("Your password could be stronger. Consider:")
                    if not strength['has_uppercase']:
                        st.write("- Add uppercase letters")
                    if not strength['has_digits']:
                        st.write("- Add numbers")
                    if not strength['has_special']:
                        st.write("- Add special characters")
                    if strength['length'] < 12:
                        st.write("- Make it longer")
                else:
                    st.success("Your password is strong!")
            else:
                st.warning("Please enter a password to check its strength.")

if __name__ == "__main__":
    main()