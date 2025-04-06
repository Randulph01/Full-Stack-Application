//this file can be replaced during build by using the 'fileReplacement' array.
//'ng build --prod 'replaces 'environment.ts' with 'environment.prof.ts'.
// The list of file replacement can be found in 'angular.json'.

export const environment = {
    production: false,
    apiUrl: 'http://localhost:4000'

};

/*
 *For easier debugging in development mode, you can import the following file
 * to ignore xone related error stack frames such as 'zone.run', 'zonedelegate.invokeTask'.
 * 
 * This import should be commented out in production mode because it will have a negative impact
 * on performance if an error is thrown.
 * /
 // import 'zone.js/dist/zone-error'; //Included with angular CLI.
 