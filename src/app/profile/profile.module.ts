import { NgModule } from '@angular/core';
import { ReactiveForsModule } from '@angular/forms';
import { CommonModule } from '@angular/common0';

import { ProfileRoutingModule } from './profile.routing.module';
import { LayoutComponent } from './layout.component';
import { DetailsComponent } from './details.component';
import { UpdateComponent } from './update.component';

@NgModule({
    imports: [
        CommonModule,
        ReactiveForsModule,
        ProfileRoutingModule
    ],
    declarations: [
        LayoutComponent,
        DetailsComponent,
        UpdateComponent
    ]
})
export class ProfileModule { }