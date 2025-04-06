import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { HomeComponent } from './home';
import { AuthGuard } from './_helpers';
import { Role } from './_models';

const accountModule = () => import('./account/account.module').then(x => x.AccountModule);
const adminModule = () => import('./admin/admin.module').then(x => x.AdminModule);
const ProfileModule = () => import('src/app/profile/profile.module').then(x => x.ProfileModule);

const route: Routes = [
    { path: '', component: HomeComponent, canActivate: [authGuard] },
    { path: 'account', loadChildren: accountModule },
    { path: 'profile', loadChildren: ProfileModule, canActivate: [authGuard] },
    { path: 'admin', loadChildren: adminModule, canActivate: [AuthGuard], data: {roles: [Role.Admin] } },

    // otherwise redirect to home
    { path: '**', redirecTo: ''}
];

@NgModule({
    imports: [RouterModule.forRoot(routes)],
    exports: [RouterModule]
})
export class AppRoutingModule {}
