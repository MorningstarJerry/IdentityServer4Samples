# IdentityServer4Samples
A demo to help you understand ids4

# Project Structure
![i1](https://github.com/MorningstarJerry/IdentityServer4Samples/blob/master/Screens/i1.png)

# Run Ids4
![i2](https://github.com/MorningstarJerry/IdentityServer4Samples/blob/master/Screens/i2.png)

## Test user
```
using IdentityModel;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer4Samples
{
    internal class Users
    {
        public static List<TestUser> Get()
        {
            return new List<TestUser> {
            new TestUser {
                SubjectId = "5BE86359-073C-434B-AD2D-A3932222DABE",
                Username = "jerry",
                Password = "JerryX123.",
                Claims = new List<Claim> {
                    new Claim(JwtClaimTypes.Email, "jerryDanks@Outlook.com"),
                    new Claim(JwtClaimTypes.Role, "admin"),
                }
            }
        };
        }
    }
}
```
## Resource
```using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4Samples
{
    internal class Resources
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new[]
            {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "role",
                UserClaims = new List<string> {"role"}
            }
        };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new[]
            {
            new ApiResource
            {
                Name = "api1",
                DisplayName = "API #1",
                Description = "Allow the application to access API #1 on your behalf",
                Scopes = new List<string> {"api1.read", "api1.write"},
                ApiSecrets = new List<Secret> {new Secret("ScopeSecret".Sha256())},
                UserClaims = new List<string> {"role"}
            }
        };
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new[]
            {
            new ApiScope("api1.read", "Read Access to API #1"),
            new ApiScope("api1.write", "Write Access to API #1")
        };
        }
    }
}
```
## Client
```
using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4Samples
{
    internal class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new List<Client>
        {
            new Client
            {
                ClientId = "oauthClient",
                ClientName = "Example client application using client credentials",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {new Secret("SuperSecretPassword".Sha256())}, // change me!
                AllowedScopes = new List<string> {"api1.read", "api1.write" }
            },
            new Client
            {
                ClientId = "oidcClient",
                ClientName = "Example Client Application",
                ClientSecrets = new List<Secret> {new Secret("SuperSecretPassword".Sha256())}, // change me!

                AllowedGrantTypes = GrantTypes.Code,
                RedirectUris = new List<string> {"https://localhost:5001/signin-oidc"},
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "role",
                    "api1.read",
                    "api1.write"
                },
                AllowAccessTokensViaBrowser=true,
            // 是否需要同意授权 （默认是false）
                RequireConsent=true,
                RequirePkce = true,
                AllowPlainTextPkce = false
            }
        };
        }
    }
}
```

# Run MVC Client
```
Install-Package Microsoft.AspNetCore.Authentication.OpenIdConnect -Version 5.0.2
Install-Package IdentityServer4.AccessTokenValidation -Version 3.0.1
```

```
  public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddAuthorization();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("Cookies")  //使用Cookie作为验证用户的首选方式
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://localhost:5000";  //授权服务器地址
                options.RequireHttpsMetadata = false;  //暂时不用https
                options.ClientId = "oidcClient";
                options.ClientSecret = "SuperSecretPassword";
                options.ResponseType = "code"; //代表Authorization Code
                options.Scope.Add("api1.read"); //添加授权资源
                options.SaveTokens = true; //表示把获取的Token存到Cookie中
                options.GetClaimsFromUserInfoEndpoint = true;
            });
        }
```
![i3](https://github.com/MorningstarJerry/IdentityServer4Samples/blob/master/Screens/i3.png)


# Call WebAPI
![i4](https://github.com/MorningstarJerry/IdentityServer4Samples/blob/master/Screens/i4.png)

Login and Copy Token to the API Request Header
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjQyN0RBRURFQjZGMzlCOTY2NDE1QzgyNEFDNjNCMEFBIiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2MTIyNDg0MTAsImV4cCI6MTYxMjI1MjAxMCwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwMCIsImF1ZCI6ImFwaTEiLCJjbGllbnRfaWQiOiJvaWRjQ2xpZW50Iiwic3ViIjoiNUJFODYzNTktMDczQy00MzRCLUFEMkQtQTM5MzIyMjJEQUJFIiwiYXV0aF90aW1lIjoxNjEyMjQ4MzY2LCJpZHAiOiJsb2NhbCIsInJvbGUiOiJhZG1pbiIsImp0aSI6IkYzRjk4M0YzNEZBMkU3RDAyNTU3Mzg1Q0UzMjIyMjc0Iiwic2lkIjoiODEwRUUxOUFGNkFGRTRBMDkwNEUwNzdBQUFCNUVENjAiLCJpYXQiOjE2MTIyNDg0MTAsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJhcGkxLnJlYWQiXSwiYW1yIjpbInB3ZCJdfQ.Rd38bMdp21TBJZX5FLHVr6JMds9_n_uhxXQ9fnhnHhPDDXeVt4TUKx9JlAwdrN1oYKHHXSeurzgFHR17csnaIw2KxTsf0rADGENvWNgfejPvupuolBJ6Z99E3pNb7ygDVCfpw6S3b4CtenJMnr_DY2_PvzafGPJUUM0nNSbxXbjSSDve_a1ugCdr0ah1_ulnNJ2jZrQukT8FkcMGrMs0DRIo3NyYLi1bBYZ0ojzD77zfrriHnqhiJnMH2tE9AM0YCybUvPM8STc9eZSfbbxasNsWbXZMb4FXjuttejxLZHACwa4AVLss7i4VTzF8nSU61IbFMAWrbbIuOnv4Ygy71w

```

![i5](https://github.com/MorningstarJerry/IdentityServer4Samples/blob/master/Screens/i5.png)



# IdentityServer4 和 ASP.NET Core 简介 Identity
https://identityserver4.readthedocs.io/en/latest/quickstarts/6_aspnet_identity.html#new-project-for-asp-net-core-identity
## ASP.NET Core 简介 Identity (针对 MVC Razor Pages 进行单体认证)

```
是一个 API，它支持用户界面) 登录功能 (UI。
管理用户、密码、配置文件数据、角色、声明、令牌、电子邮件确认等。
```

## Authentication + Authorization

```
OpenID  (Authentication 认证) 是一个以用户为中心的数字身份识别框架，它具有开放、分散性。OpenID 的创建基于这样一个概念：我们可以通过 URI （又叫 URL 或网站地址）来认证一个网站的唯一身份，同理，我们也可以通过这种方式来作为用户的身份认证。
```

```
OAuth（Authorization 开放授权）是一个开放标准，目前的版本是2.0。允许用户授权第三方移动应用访问他们存储在其他服务商上存储的私密的资源（如照片，视频，联系人列表），而无需将用户名和密码提供给第三方应用。
```

```
OpenID Connect 1.0 是基于OAuth 2.0协议之上的简单身份层，它允许客户端根据授权服务器的认证结果最终确认终端用户的身份，以及获取基本的用户信息；它支持包括Web、移动、JavaScript在内的所有客户端类型去请求和接收终端用户信息和身份认证会话信息；它是可扩展的协议，允许你使用某些可选功能，如身份数据加密、OpenID提供商发现、会话管理等。
```

`OpenId Connect = OIDC = Authentication + Authorization + OAuth2.0`

## 认证模式 （HTTP身份验证流程 + JWT）

Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（RFC 7519）。该token被设计为紧凑且安全的，特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。

* Header：由alg和typ组成，alg是algorithm的缩写，typ是type的缩写，指定token的类型。该部 分使用Base64Url编码。
* Payload：主要用来存储信息，包含各种声明，同样该部分也由BaseURL编码。
* Signature：签名，使用服务器端的密钥进行签名。以确保Token未被篡改。

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

## OAuth2.0 定义了四种授权模式：

* 1.Implicit：简化模式；直接通过浏览器的链接跳转申请令牌。
* 2.Client Credentials：客户端凭证模式；该方法通常用于服务器之间的通讯；该模式仅发生在Client与Identity Server之间。
* 3.Resource Owner Password Credentials：密码模式。(终端用户到受保护的资源之间)
* 4.Authorization Code：授权码模式；

### Client Credentials

```
客户端凭证模式，是最简单的授权模式，因为授权的流程仅发生在Client与Identity Server之间。该模式的适用场景为服务器与服务器之间的通信。比如对于一个电子商务网站，将订单和物流系统分拆为两个服务分别部署。订单系统需要访问物流系统进行物流信息的跟踪，物流系统需要访问订单系统的快递单号信息进行物流信息的定时刷新。而这两个系统之间服务的授权就可以通过这种模式来实现。
```

### Resource Owner Password Credentials

```
Resource Owner其实就是User，所以可以直译为用户名密码模式。密码模式相较于客户端凭证模式，多了一个参与者，就是User。通过User的用户名和密码向Identity Server申请访问令牌。这种模式下要求客户端不得储存密码。但我们并不能确保客户端是否储存了密码，所以该模式仅适用于受信任的客户端。否则会发生密码泄露的危险。该模式不推荐使用。
```

### Authorization Code

```
授权码模式是一种混合模式，是目前功能最完整、流程最严密的授权模式。它主要分为两大步骤：认证和授权。 其流程为：

用户访问客户端，客户端将用户导向Identity Server。
用户填写凭证信息向客户端授权，认证服务器根据客户端指定的重定向URI，并返回一个【Authorization Code】给客户端。
客户端根据【Authorization Code】向Identity Server申请【Access Token】
```

### Implicit

```
简化模式是相对于授权码模式而言的。其不再需要【Client】的参与，所有的认证和授权都是通过浏览器来完成的。
```

# IndentityServer4


https://identityserver4.readthedocs.io/en/latest/index.html

https://www.cnblogs.com/stulzq/p/8119928.html

## IdentityServer4是为ASP.NET CORE量身定制的实现了OpenId Connect和OAuth2.0协议的认证授权中间件。

<img src="C:\Users\2294765\AppData\Roaming\Typora\typora-user-images\image-20201216110304560.png" alt="image-20201216110304560" style="zoom:50%;" />

# Get Start With IndentityServer 4

https://www.scottbrady91.com/Identity-Server/Getting-Started-with-IdentityServer-4
https://github.com/IdentityServer/IdentityServer4.Demo.git
https://www.cnblogs.com/Zing/p/13366318.html



# Ids4 加入 asp.net Client 和 js Client

https://identityserver4.readthedocs.io/en/latest/quickstarts/4_javascript_client.html#new-project-for-the-javascript-client

# Vue 中引入 oidc-client

`npm install oidc-client`

https://www.cnblogs.com/FireworksEasyCool/p/10576911.html

```
<template></template>

<script>
import Oidc from "oidc-client";

var config = {
  authority: "http://localhost:5000",
  client_id: "js",
  redirect_uri: "http://localhost:5003/CallBack",
  response_type: "id_token token",
  scope: "openid profile api1",
  post_logout_redirect_uri: "http://localhost:5003/"
};
var mgr = new Oidc.UserManager(config);
export default {
  beforeCreate() {
    mgr.signinRedirect();
  }
};
</script>
```



# aspnet core identity 集成 ids4

https://identityserver4.readthedocs.io/en/latest/quickstarts/6_aspnet_identity.html



