using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using System;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace MentoryWebAuthProject
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder();
            string connection = builder.Configuration.GetConnectionString("DefaultConnection");
            builder.Services.AddDbContext<ApplicationContext>(options => options.UseSqlServer(connection));
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options => options.LoginPath = "/login");
            builder.Services.AddAuthorization();

            var app = builder.Build();
            app.UseAuthentication();   // добавление middleware аутентификации 
            app.UseAuthorization();   // добавление middleware авторизации 

            
            

            app.MapGet("/login", async (HttpContext context) =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.SendFileAsync("html\\login.html");
            });

            app.MapPost("/login", async (string? returnUrl, HttpContext context, ApplicationContext db) =>
            {
                // получаем из формы email и пароль
                var form = context.Request.Form;
                // если email и/или пароль не установлены, посылаем статусный код ошибки 400
                if (!form.ContainsKey("email") || !form.ContainsKey("password"))
                    return Results.BadRequest("Email и/или пароль не установлены");

                string email = form["email"];
                string password = Person.GetHash(form["password"]);

                // находим пользователя 
                Person? person = db.People.FirstOrDefault(p => p.Email == email && p.PassHash == password);

                // если пользователь не найден, отправляем статусный код 401
                if (person is null) return Results.Unauthorized();

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, person.Email) };
                // создаем объект ClaimsIdentity
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Cookies");
                // установка аутентификационных куки
                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
                return Results.Redirect(returnUrl ?? "/");
            });

            app.MapGet("/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return Results.Redirect("/login");
            });

            app.Map("/", [Authorize] async (HttpContext context) =>
            {
                context.Response.ContentType = "text/html";
                await context.Response.SendFileAsync("html\\index.html");
            });

            app.MapGet("/api/users", [Authorize] async (ApplicationContext db) => await db.Users.ToListAsync());

            app.MapGet("/api/users/{id:int}", [Authorize] async (int id, ApplicationContext db) =>
            {
                // получаем пользователя по id
                User? user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, отправляем его
                return Results.Json(user);
            });

            app.MapDelete("/api/users/{id:int}", [Authorize] async (int id, ApplicationContext db) =>
            {
                // получаем пользователя по id
                User? user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, удаляем его
                db.Users.Remove(user);
                await db.SaveChangesAsync();
                return Results.Json(user);
            });

            app.MapPost("/api/users", [Authorize] async (User user, ApplicationContext db) =>
            {
                // добавляем пользователя в массив
                await db.Users.AddAsync(user);
                await db.SaveChangesAsync();
                return user;
            });

            app.MapPut("/api/users", [Authorize] async (User userData, ApplicationContext db) =>
            {
                // получаем пользователя по id
                var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userData.Id);

                // если не найден, отправляем статусный код и сообщение об ошибке
                if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });

                // если пользователь найден, изменяем его данные и отправляем обратно клиенту
                user.Age = userData.Age;
                user.Name = userData.Name;
                await db.SaveChangesAsync();
                return Results.Json(user);
            });

            app.Run();
        }
    }
}
