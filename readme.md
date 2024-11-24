# Implementation Notes:

- **Used JWT-Based Authentication (Utilized the LexikJWTAuthenticationBundle)**

- **Impersonation Feature: Super admins can obtain JWT tokens of other users via the `/impersonate` route, allowing them to perform actions on behalf of those users seamlessly.**

- **Attempted to Utilize Symfony's internal `API Platform` to use predefined routes, manage user roles, etc.**

- **All routes manually tested using Postman; some screenshots are available in the `screenshots` folder.**

- **Key Scenarios are Covered by Unit Tests in the `test` folder.**

- **API documentation and an online try-it interface are accessible via the `/api/docs` route (OpenAPI).**