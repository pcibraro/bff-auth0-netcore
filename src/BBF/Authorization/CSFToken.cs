using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackendAsFrontend.Authorization
{
    public class CSFToken : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            if (context.HttpContext.User.Identity.IsAuthenticated)
            {
                var header = context.HttpContext.Request.Headers["X-CSRF-Token"];
                var cookie = context.HttpContext.Request.Cookies["X-CSRF-Token"];

                if (header != cookie)
                {
                    context.Result = new UnauthorizedResult();

                    return;
                }
            }
            
            base.OnActionExecuting(context);
        }
    }
}
