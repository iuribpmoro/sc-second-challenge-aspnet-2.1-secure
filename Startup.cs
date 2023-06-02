using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

// Libs to fix XSS
using System.Text.RegularExpressions; // to use Regex.IsMatch
using System.Web; // to use HttpUtility.HtmlEncode

// Import Path
using System.IO;

// Import CSRF Token
using Microsoft.AspNetCore.Antiforgery;

namespace second_challenge_21
{
    public class User
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public decimal Price { get; set; }
        public string Image { get; set; }
    }

    public static class AuthenticationMiddlewareExtensions
    {
        public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder app)
        {
            return app.Use(async (context, next) =>
            {
                var userIdString = context.Session.GetString("UserId");

                if (string.IsNullOrEmpty(userIdString))
                {
                    context.Response.Redirect("/");
                    return;
                }

                await next();
            });
        }
    }
    
    public class Startup
    {
        private static readonly List<User> users = new List<User>
        {
            new User { Id = Guid.NewGuid(), Name = "Alice", Email = "alice@example.com", Password = "password1" },
            new User { Id = Guid.NewGuid(), Name = "Bob", Email = "bob@example.com", Password = "password2" },
            new User { Id = Guid.NewGuid(), Name = "Charlie", Email = "charlie@example.com", Password = "password3" }
        };

        private static readonly List<Product> products = new List<Product>
        {
            new Product { Id = 1, Name = "Shoes", Price = 50, Image = "shoes.jpg" },
            new Product { Id = 2, Name = "Apple", Price = 5, Image = "apple.png" },
            new Product { Id = 3, Name = "Hat", Price = 15, Image = "hat.jpg" }
        };
        
        private IAntiforgery antiforgery;

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddSession(options =>
            {
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });
            services.AddDistributedMemoryCache();

            // Adicionar serviço antiforgery para proteger contra CSRF
            services.AddAntiforgery(options =>
            {
                options.FormFieldName = "__CSRF";
                options.Cookie.Name = "CSRF-TOKEN";
                options.SuppressXFrameOptionsHeader = false;
            });
        }

        private static bool IsWhitelisted(string path)
        {
            var whitelist = new[] { "/", "/login" };
            return whitelist.Contains(path);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IAntiforgery antiforgery)
        {
            this.antiforgery = antiforgery;
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSession();

            // Authentication middleware called only when the path is not whitelisted
            app.UseWhen(context => !IsWhitelisted(context.Request.Path), appBuilder =>
            {
                appBuilder.UseAuthenticationMiddleware();
            });

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

            app.Run(async (context) =>
            {
                if (context.Request.Path == "/")
                {
                    await context.Response.WriteAsync(@"
                        <h1>Welcome to the Store</h1>
                        <form action=""/login"" method=""post"">
                            <label for=""email"">Email:</label>
                            <input type=""email"" name=""email"" id=""email"" required>
                            <label for=""password"">Password:</label>
                            <input type=""password"" name=""password"" id=""password"" required>
                            <button type=""submit"">Login</button>
                        </form>
                    ");
                }
                else if (context.Request.Path == "/login" && context.Request.Method == "POST")
                {
                    var email = context.Request.Form["email"];
                    var password = context.Request.Form["password"];
                    var user = users.Find(u => u.Email == email && u.Password == password);

                    if (user != null)
                    {
                        context.Session.SetString("UserId", user.Id.ToString());
                        context.Response.Redirect($"/products");
                    }
                    else
                    {
                        await context.Response.WriteAsync("Invalid credentials. Please try again.");
                    }
                }
                else if (context.Request.Path.StartsWithSegments("/products") && context.Request.Method == "GET")
                {
                    var userIdString = context.Session.GetString("UserId");

                    if (string.IsNullOrEmpty(userIdString))
                    {
                        context.Response.Redirect("/");
                        await System.Threading.Tasks.Task.CompletedTask;
                        return;
                    }

                    var userId = Guid.Parse(userIdString);
                    var user = users.Find(u => u.Id == userId);

                    if (user != null)
                    {
                        var tokenSet = antiforgery.GetAndStoreTokens(context);
                        var token = tokenSet.RequestToken;
                        
                        var productsHtml = string.Join("", products.Select(p => $@"
                            <li>
                                <img src=""/images?name={p.Image}"" alt=""{p.Name}"" width=""100"">
                                <h3>{p.Name}</h3>
                                <p>Price: ${p.Price}</p>
                                <form action=""/place-order"" method=""post"">
                                    <input type=""hidden"" name=""product_id"" value=""{p.Id}"">
                                    <input type=""hidden"" name=""__CSRF"" value=""{token}"">
                                    <button type=""submit"">Place Order</button>
                                </form>
                            </li>
                        "));

                        await context.Response.WriteAsync($@"
                            <h1>Product Listing</h1>
                            <ul>
                                {productsHtml}
                            </ul>
                        ");

                        return;
                    }

                    context.Response.Redirect("/");
                    await System.Threading.Tasks.Task.CompletedTask;
                    return;
                }
                else if (context.Request.Path.StartsWithSegments("/images") && context.Request.Method == "GET")
                {
                    var imageName = context.Request.Query["name"].ToString();

                    // Filtro para evitar Path Traversal
                    string pattern = @"^[a-zA-Z0-9.\s]*$";
                    if (!Regex.IsMatch(imageName, pattern))
                    {
                        await context.Response.WriteAsync("Invalid image name!");
                        return;
                    }

                    // Define base path
                    string basePath = Path.GetFullPath("public/images");
                    var filePath = Path.Combine(basePath, imageName);

                    // Cannonicalize path
                    filePath = Path.GetFullPath(filePath);

                    // Check if filename is inside the base path
                    if (!filePath.StartsWith(basePath))
                    {
                        await context.Response.WriteAsync("Invalid image name!");
                        return;
                    }
                    else if (!File.Exists(filePath))
                    {
                        await context.Response.WriteAsync("Image not found!");
                        return;
                    }

                    await context.Response.SendFileAsync(filePath);
                    return;
                }
                else if (context.Request.Path == "/place-order" && context.Request.Method == "POST")
                {
                    var userIdString = context.Session.GetString("UserId");

                    if (string.IsNullOrEmpty(userIdString))
                    {
                        context.Response.Redirect("/");
                        await System.Threading.Tasks.Task.CompletedTask;
                        return;
                    }

                    var userId = Guid.Parse(userIdString);
                    var user = users.Find(u => u.Id == userId);
                    var productId = int.Parse(context.Request.Form["product_id"]);

                    if (user != null)
                    {
                        // Validate the CSRF token
                        var antiforgeryInstance = context.RequestServices.GetRequiredService<IAntiforgery>();

                        var valid = await antiforgeryInstance.IsRequestValidAsync(context);

                        if (!valid)
                        {
                            context.Response.StatusCode = 403;
                            await context.Response.WriteAsync("CSRF validation failed");
                            return;
                        }
                        
                        var product = products.Find(p => p.Id == productId);

                        if (product != null)
                        {
                            await context.Response.WriteAsync($@"
                                <h1>Order Placed</h1>
                                <p>Thank you for placing an order for {product.Name}.</p>
                            ");

                            return;
                        }
                        else
                        {
                            context.Response.StatusCode = 404;
                            await context.Response.WriteAsync("Product not found");
                            return;
                        }
                    }

                    context.Response.Redirect("/");
                    await System.Threading.Tasks.Task.CompletedTask;
                    return;
                }
                else
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("Page not found");
                    return;
                }
            });
        }
    }
}
