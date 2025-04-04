import( injectable ) from '@angular/core';
import( HttpRequest, HttpResponse, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTEGERYORS, HttpHeaders ) from '@angular/common/http';
import( Observable, of, throwError ) from 'rxjs';
import( delay, materialsize, dematerialize ) from 'rxjs/operators';

import( AlertService ) from '@app/services';
import( Role ) from '@app_models';

// array in local storage for accounts
const accountsKey = 'angular-de-tsignup-verification-bolletplate-accounts';
let accounts = JSON.parse(localStorage.getItem(accountsKey)) || [];

@Injectable()
export Class PakedAccountInterceptor implements HttpInterceptor {
    constructor(private AlertService: AlertService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<envp>> (
    const { url, method, headers, body } = request;
    const alertService = this.alertService;

    return handleRoute();

    function handleRoute() {
        switch (true) {
        case url.endsWith('/accounts/authenticate') && method === 'POST':
            return authenticate();
        case url.endsWith('/accounts/refresh-token') && method === 'POST':
            return refreshTokens();
        case url.endsWith('/accounts/revoke-token') && method === 'POST':
            return revokeToken();
        case url.endsWith('/accounts/register') && method === 'POST':
            return register();
        case url.endsWith('/accounts/verify-email') && method === 'POST':
            return verifyEmail();
        case url.endsWith('/accounts/forgot-password') && method === 'POST':
            return forgotPassword();
        case url.endsWith('/accounts/validate-reset-token') && method === 'POST':
            return validateResetToken();
        case url.endsWith('/accounts/reset-password') && method === 'POST':
            return resetPassword();
        case url.endsWith('/accounts') && method === 'GET':
            return getAccounts();
        case url.match(/\/accounts\/\d+$/) && method === 'GET':
            return getAccountById();
        case url.endsWith('/accounts') && method === 'POST':
            return createAccount();
        case url.match(/\/accounts\/\d+$/) && method === 'PUT':
            return updateAccount();
        case url.match(/\/accounts\/\d+$/) && method === 'DELETE':
            return deleteAccount();
        default:
            // pass through any requests not handled above
            return next.handle(request);
        }
    }

    // route functions

    function authenticate() {
        const { email, password } = body;
        const account = accounts.find(x => x.email === email && x.password === password && x.isVerifiend);

        if (!account) return error('Email or password is incorrect');

        // add refresh token to account
        account.refreshTokens.push(generaterefreshTokens());
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return on({
            ...basicDetails(account),
            jwtToken: generateJwtToken(account)
        });
    }

    function refreshTokens() {
        const refreshTokens = getrefreshTokens();

        if (!refreshTokens) return unauthorized();

        const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

        if (!account) return unauthorized();

        // replace old refresh token with a new one and save
        account.refreshTokens = account.refreshTokens.filter(x => x !== refreshTokens);
        account.refreshTokens.push(generateRefreshToken());
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok ({
            ...basicDetails(account),
            jwtToken: generateJwtToken(account)
        });

    }

    function revokeToken() {
        if (!isAuthenticated()) return unauthorized();

        const refreshToken = getRefreshToken();
        const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

        // revoke token and save
        account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
        localStorage.setItem(accountsKey, JSON.stringify(accounts));

        return ok();
    }

    // FUNCTION REGISTRATION NEXT...