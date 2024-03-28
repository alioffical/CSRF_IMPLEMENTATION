using CSRF_IMPLEMENTATION.Models;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Diagnostics;

namespace CSRF_IMPLEMENTATION.Controllers
{
    public class HomeController : Controller
    {
        private readonly string _connectionString;
        private readonly IAntiforgery _antiforgery;

        public HomeController(IConfiguration configuration, IAntiforgery antiforgery)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
            _antiforgery = antiforgery;
        }

        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public ActionResult SubmitForm()
        {
            return View();
        }

        [HttpPost]
        public ActionResult SubmitForm(string name, string password)
        {
            if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(password))
            {
                HttpContext.Session.SetString("Username", name);

                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    var sql = "INSERT INTO Users (Username, Password) VALUES (@Username, @Password)";
                    using (var command = new SqlCommand(sql, connection))
                    {
                        command.Parameters.AddWithValue("@Username", name);
                        command.Parameters.AddWithValue("@Password", password);
                        command.ExecuteNonQuery();
                    }
                }

                ViewBag.Username = name;
                return View("SubmittedForm");
            }
            else
            {
                ViewBag.Error = "Username and password are required.";
                return View();
            }
        }

        public IActionResult ChangeEmail()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ChangeEmail(string newEmail)
        {
           
            string username = HttpContext.Request.Cookies["Username"];

            if (!string.IsNullOrEmpty(username))
            {
                
                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    var sql = "UPDATE Users SET Email = @NewEmail WHERE Username = @Username";
                    using (var command = new SqlCommand(sql, connection))
                    {
                        command.Parameters.AddWithValue("@NewEmail", newEmail);
                        command.Parameters.AddWithValue("@Username", username);
                        int rowsAffected = command.ExecuteNonQuery();

                        
                        if (rowsAffected > 0)
                        {
                            ViewBag.SuccessMessage = "Email updated successfully.";
                        }
                        else
                        {
                            ViewBag.ErrorMessage = "Failed to update email. User not found.";
                        }
                    }
                }
            }
            else
            {
                ViewBag.ErrorMessage = "Username not found in the cookie.";
            }

            return Ok();
        }


        public ActionResult CSRFSubmitForm()
        {
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult CSRFSubmitForm(string name, string email)
        {

            
            if (!ValidateCsrfToken())
            {
                
                return BadRequest("Invalid CSRF token.");
            }

            
            if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(email))
            {
                
                using (var connection = new SqlConnection(_connectionString))
                {
                    connection.Open();
                    var sql = "INSERT INTO Users (Username, Email) VALUES (@Name, @Email)";
                    using (var command = new SqlCommand(sql, connection))
                    {
                        command.Parameters.AddWithValue("@Name", name);
                        command.Parameters.AddWithValue("@Email", email);
                        command.ExecuteNonQuery();
                    }
                }


                
                ViewBag.Name = name;
                ViewBag.Email = email;
                return View("SubmittedForm");
            }
            else
            {
                return BadRequest("Name and email are required.");
            }
        }

        private bool ValidateCsrfToken()
        {
            try
            {
                
                var requestToken = HttpContext.Request.Form["__RequestVerificationToken"];

                _antiforgery.ValidateRequestAsync(HttpContext).Wait();
                var tokenSet = _antiforgery.GetAndStoreTokens(HttpContext);
                var generatedToken = tokenSet.RequestToken;
                return string.Equals(requestToken, generatedToken);
            }
            catch (Exception)
            {
                return false;
            }
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                ViewBag.Error = "Username and password are required.";
                return View();
            }

            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var sql = "SELECT COUNT(*) FROM Users WHERE Username = @Username AND Password = @Password";
                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Password", password);
                    int count = (int)command.ExecuteScalar();

                    if (count > 0) 
                    {
                        HttpContext.Session.SetString("Username", username);
                        return RedirectToAction("Index", "Home"); 
                    }
                    else
                    {
                        ViewBag.Error = "Invalid username or password.";
                        return View();
                    }
                }
            }
        }


    }
}
