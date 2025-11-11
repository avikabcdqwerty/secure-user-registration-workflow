import React, { useState } from 'react';
import PropTypes from 'prop-types';

// Password strength meter utility
const getPasswordStrength = (password) => {
  // Returns score: 0 (empty), 1 (weak), 2 (medium), 3 (strong), 4 (very strong)
  let score = 0;
  if (!password) return score;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  // Only count as strong if all criteria met
  if (score >= 5) return 4;
  if (score >= 3) return 3;
  if (score === 2) return 2;
  return 1;
};

const strengthLabels = [
  'Empty',
  'Weak',
  'Medium',
  'Strong',
  'Very Strong'
];

const strengthColors = [
  '#ccc',
  '#e53935',
  '#fbc02d',
  '#43a047',
  '#1e88e5'
];

// Email RFC 5322 validation regex (simplified for UI)
const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;

// RegistrationForm component
/**
 * RegistrationForm
 * React component for secure user registration.
 * Displays email and password fields, password strength meter, and handles registration.
 */
const RegistrationForm = ({ apiUrl }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [formError, setFormError] = useState('');
  const [formSuccess, setFormSuccess] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Validate email format
  const validateEmail = (value) => {
    if (!value) return 'Email is required.';
    if (!emailRegex.test(value)) return 'Invalid email format.';
    return '';
  };

  // Validate password strength
  const validatePassword = (value) => {
    if (!value) return 'Password is required.';
    if (value.length < 12) return 'Password must be at least 12 characters.';
    if (!/[A-Z]/.test(value)) return 'Password must contain an uppercase letter.';
    if (!/[a-z]/.test(value)) return 'Password must contain a lowercase letter.';
    if (!/\d/.test(value)) return 'Password must contain a digit.';
    if (!/[^A-Za-z0-9]/.test(value)) return 'Password must contain a special character.';
    return '';
  };

  // Handle input changes
  const handleEmailChange = (e) => {
    setEmail(e.target.value);
    setEmailError('');
    setFormError('');
    setFormSuccess('');
  };

  const handlePasswordChange = (e) => {
    const value = e.target.value;
    setPassword(value);
    setPasswordStrength(getPasswordStrength(value));
    setPasswordError('');
    setFormError('');
    setFormSuccess('');
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    setFormSuccess('');

    // Validate inputs
    const emailErr = validateEmail(email);
    const passwordErr = validatePassword(password);

    setEmailError(emailErr);
    setPasswordError(passwordErr);

    if (emailErr || passwordErr) {
      setFormError('Please fix the errors above.');
      return;
    }

    setIsSubmitting(true);

    try {
      // Send registration request
      const response = await fetch(`${apiUrl}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        setFormSuccess(data.message || 'Registration successful. Please check your email to confirm your account.');
        setEmail('');
        setPassword('');
        setPasswordStrength(0);
      } else {
        // Show error from backend, sanitize message
        setFormError(data.detail ? String(data.detail) : 'Registration failed. Please try again.');
      }
    } catch (err) {
      // Log error for debugging (do not expose sensitive info)
      // eslint-disable-next-line no-console
      console.error('Registration error:', err);
      setFormError('Network error. Please try again later.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form className="registration-form" onSubmit={handleSubmit} autoComplete="off" noValidate>
      <h2>Create Account</h2>
      <div className="form-group">
        <label htmlFor="email">Email Address</label>
        <input
          type="email"
          id="email"
          name="email"
          autoComplete="username"
          value={email}
          onChange={handleEmailChange}
          required
          aria-describedby="emailHelp"
          aria-invalid={!!emailError}
        />
        {emailError && <div className="error" role="alert">{emailError}</div>}
      </div>
      <div className="form-group">
        <label htmlFor="password">Password</label>
        <input
          type="password"
          id="password"
          name="password"
          autoComplete="new-password"
          value={password}
          onChange={handlePasswordChange}
          required
          aria-describedby="passwordHelp"
          aria-invalid={!!passwordError}
        />
        <PasswordStrengthMeter strength={passwordStrength} password={password} />
        {passwordError && <div className="error" role="alert">{passwordError}</div>}
        <small id="passwordHelp" className="form-text">
          Minimum 12 characters, including uppercase, lowercase, digit, and special character.
        </small>
      </div>
      <button
        type="submit"
        className="btn btn-primary"
        disabled={isSubmitting}
        aria-busy={isSubmitting}
      >
        {isSubmitting ? 'Registering...' : 'Register'}
      </button>
      {formError && <div className="error" role="alert">{formError}</div>}
      {formSuccess && <div className="success" role="status">{formSuccess}</div>}
    </form>
  );
};

// PasswordStrengthMeter subcomponent
const PasswordStrengthMeter = ({ strength, password }) => {
  const percent = (strength / 4) * 100;
  const color = strengthColors[strength];
  const label = strengthLabels[strength];

  return (
    <div className="password-strength-meter" aria-live="polite">
      <div
        className="strength-bar"
        style={{
          width: `${percent}%`,
          backgroundColor: color,
          height: '8px',
          borderRadius: '4px',
          transition: 'width 0.3s, background-color 0.3s'
        }}
      />
      <span className="strength-label" style={{ color, fontWeight: 'bold', marginLeft: '8px' }}>
        {password ? label : ''}
      </span>
    </div>
  );
};

PasswordStrengthMeter.propTypes = {
  strength: PropTypes.number.isRequired,
  password: PropTypes.string.isRequired
};

RegistrationForm.propTypes = {
  apiUrl: PropTypes.string.isRequired // e.g., 'https://api.example.com'
};

export default RegistrationForm;