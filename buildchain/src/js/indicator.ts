// Declarations
declare let passwordpolicy: {
    showStrengthIndicator: boolean;
};

// Import our CSS
import '~/css/app.css';

import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en'

const options = {
    dictionary: {
        ...zxcvbnCommonPackage.dictionary,
        ...zxcvbnEnPackage.dictionary,
    },
}
zxcvbnOptions.setOptions(options)

const newPasswordField = document.getElementById('newPassword')
const wrapper = document.getElementById('newPassword-field')

const strength : { [key: number]: string } = {
    0: 'pp-bg-red-400',
    1: 'pp-bg-orange-400',
    2: 'pp-bg-amber-300',
    3: 'pp-bg-teal-400',
    4: 'pp-bg-green-500',
}

const passwordStrength : { score: number|null } = {
    score: null,
}

// Function to dynamically generate the password bar
function generatePasswordBar(score: number | null): string {
    const defaultClass = 'pp-bg-slate-200 pp-h-2';
    const activeClass = score !== null ? strength[score] : defaultClass;

    const bars = Array.from({ length: 5 }, (_, index) =>
        `<span class="${index <= (score ?? -1) ? activeClass : defaultClass}"></span>`
    ).join('');

    return `
        <div id="password-strength-bar" class="pp-grid pp-grid-cols-5 pp-gap-x-1 pp-h-2 -pp-mt-4">
            ${bars}
        </div>`;
}

if (newPasswordField && passwordpolicy.showStrengthIndicator) {
    wrapper?.insertAdjacentHTML('afterend', generatePasswordBar(passwordStrength.score))

    newPasswordField.addEventListener('input', function (event) {
        const target = event.currentTarget as HTMLInputElement;
        const password = target.value

        if (password.length > 0) {
            const details = zxcvbn(password)
            passwordStrength.score = details.score
        }

        // Remove existing password bar
        const currentBar = document.getElementById('password-strength-bar');
        if (currentBar) {
            currentBar.remove();
        }

        wrapper?.insertAdjacentHTML('afterend', generatePasswordBar(password.length > 0 ? passwordStrength.score : null));
    })
}
