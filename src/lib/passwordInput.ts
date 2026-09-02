// Behaviour for the PasswordInput component: visibility toggle, dice generation, and the
// overflow fades. Both the simple and advanced calculators mount the same box, so this
// lives here rather than being copy-pasted into each page's script.

import { calculateEntropy } from '@lib/calculations';
import { loadWordlist, generatePassphrase, DEFAULT_WORD_COUNT } from '@lib/generator';

export interface PasswordInputHandle {
  /**
   * Current password and generated-entropy state. Pages that recompute for reasons other
   * than a password change (a changed algorithm, say) read it rather than caching a copy.
   */
  getState(): PasswordState;
}

export interface PasswordState {
  password: string;
  /**
   * Exact entropy of a passphrase we generated, or null when the user typed the password
   * themselves — hand-entered passwords fall back to the zxcvbn estimate.
   */
  generatedEntropy: number | null;
}

/**
 * Wires up the password box and calls `onChange` whenever the password changes.
 *
 * Call once per page, after the DOM is ready. The component renders a single box with
 * fixed ids, so there is one instance per page.
 */
export function initPasswordInput(onChange: (state: PasswordState) => void): PasswordInputHandle {
  const passwordInput = document.getElementById('password') as HTMLInputElement;
  const toggleVisibility = document.getElementById('toggle-visibility') as HTMLButtonElement;
  const generateButton = document.getElementById('generate-password') as HTMLButtonElement;
  const passwordField = document.getElementById('password-field') as HTMLDivElement;

  let isPasswordVisible = true;
  let generatedEntropy: number | null = null;
  let hasReceivedFirstFocus = false;

  const emit = () => {
    updateOverflowFades();  // the value may have changed programmatically
    onChange({ password: passwordInput.value, generatedEntropy });
  };

  /**
   * Show a fade on whichever side the password continues past the edge of the box.
   */
  function updateOverflowFades() {
    const overflow = passwordInput.scrollWidth - passwordInput.clientWidth;
    const scrolled = passwordInput.scrollLeft;

    passwordField.classList.toggle('overflow-left', overflow > 1 && scrolled > 1);
    passwordField.classList.toggle('overflow-right', overflow > 1 && scrolled < overflow - 1);
  }

  function togglePasswordVisibility() {
    isPasswordVisible = !isPasswordVisible;
    passwordInput.type = isPasswordVisible ? 'text' : 'password';

    const eyeIcon = toggleVisibility.querySelector('.eye-icon') as SVGElement;
    const eyeOffIcon = toggleVisibility.querySelector('.eye-off-icon') as SVGElement;

    if (isPasswordVisible) {
      eyeIcon.classList.remove('hidden');
      eyeOffIcon.classList.add('hidden');
    } else {
      eyeIcon.classList.add('hidden');
      eyeOffIcon.classList.remove('hidden');
    }

    const label = isPasswordVisible ? 'Hide password' : 'Show password';
    toggleVisibility.setAttribute('data-tooltip', label);
    toggleVisibility.setAttribute('aria-label', label);
  }

  async function generateIntoInput() {
    const diceIcon = generateButton.querySelector('.dice-icon') as SVGElement;
    diceIcon.classList.remove('rolling');
    diceIcon.getBoundingClientRect();  // force a reflow so the animation restarts on every click
    diceIcon.classList.add('rolling');
    generateButton.disabled = true;

    try {
      const wordlist = await loadWordlist();
      const { passphrase, entropy } = generatePassphrase(wordlist, {
        wordCount: DEFAULT_WORD_COUNT,
        estimateEntropy: calculateEntropy,
      });

      generatedEntropy = entropy;
      passwordInput.value = passphrase;

      // A passphrase you cannot read is no use, so reveal it and stop the first-focus hide
      hasReceivedFirstFocus = true;
      if (!isPasswordVisible) togglePasswordVisibility();

      emit();
    } catch (error) {
      console.error('Could not generate a passphrase:', error);
    } finally {
      generateButton.disabled = false;
    }
  }

  passwordInput.addEventListener('input', () => {
    generatedEntropy = null;  // hand-edited, so fall back to the zxcvbn estimate
    emit();
  });
  generateButton.addEventListener('click', generateIntoInput);
  toggleVisibility.addEventListener('click', () => {
    togglePasswordVisibility();
    updateOverflowFades();  // dots and characters are not the same width
  });
  passwordInput.addEventListener('scroll', updateOverflowFades);
  window.addEventListener('resize', updateOverflowFades);
  updateOverflowFades();

  passwordInput.addEventListener('focus', () => {
    // On first focus, hide the password and select all text
    if (!hasReceivedFirstFocus) {
      hasReceivedFirstFocus = true;
      if (isPasswordVisible) {
        togglePasswordVisibility();
      }
    }
    passwordInput.select();
  });

  return {
    getState: () => ({ password: passwordInput.value, generatedEntropy }),
  };
}
