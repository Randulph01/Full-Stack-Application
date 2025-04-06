import {Component} from '@angular/core';

import {AccountService} from '@app/_services'

@Component({ templateUrl: 'home.component.html'})
export class HomeComponent {
    account = this.accountSevice.accountValue;

    constructor( private accountService: AccountService ) { }
    
}
