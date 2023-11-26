import { Component, OnInit } from "@angular/core";
import { User } from "src/app/model/user.model";
import { NgForm } from "@angular/forms";
import { LoginService } from "src/app/services/login/login.service";
import { Router } from "@angular/router";
import { getCookie } from "typescript-cookie";

@Component({
  selector: "app-login",
  templateUrl: "./login.component.html",
  styleUrls: ["./login.component.css"],
})
export class LoginComponent implements OnInit {
  authStatus: string = "";
  model = new User();

  constructor(private loginService: LoginService, private router: Router) {}

  ngOnInit(): void {}

  validateUser(loginForm: NgForm) {
    this.loginService
      .validateLoginDetails(this.model)
      .subscribe((responseData) => {
        /**
         * It's common practice to store authentication-related JWT tokens in the session storage of web applications.
         *  This allows for later use, especially when making authenticated requests.
         */
        window.sessionStorage.setItem("Authorization",responseData.headers.get('Authorization')!);
        
        this.model = <any>responseData.body;
        /**
         * Retrieving XSRF-TOKEN from a Cookie
         * This line attempts to retrieve the value of a cookie named "XSRF-TOKEN" using a custom function called getCookie.
         *  The XSRF token is commonly used for CSRF (Cross-Site Request Forgery) protection and is often stored in a cookie.
         */
        let xsrf = getCookie('XSRF-TOKEN')!;
        window.sessionStorage.setItem("XSRF-TOKEN",xsrf);

          /*
         Storing User Details in Session Storage
         This line stores the serialized JSON representation of this.model in the session storage under the key "userdetails."
          sessionStorage is part of the Web Storage API, allowing the storage of key-value pairs with a session lifetime.
         */
        this.model.authStatus = "AUTH";
        window.sessionStorage.setItem(
          "userdetails",
          JSON.stringify(this.model)
        );
        this.router.navigate(["dashboard"]);
      });
  }
}
