﻿using DotNetAuth.Domain.Constructs;
using Microsoft.AspNetCore.Diagnostics;
using System.Net;

namespace DotNetAuth.Exceptions
{
    public class GlobalExceptionHandler : IExceptionHandler
    {
        private readonly ILogger<GlobalExceptionHandler> _logger;

        public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
        {
            _logger = logger;
        }

        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            _logger.LogError(exception, exception.Message);
            var response = new ErrorResponse
            {
                Message = exception.Message,
            };

            switch (exception)
            {
                case BadHttpRequestException:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Titel = exception.GetType().Name;
                    break;

                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response.Titel = exception.GetType().Name;
                    break;

                case KeyNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Titel = exception.GetType().Name;
                    break;

                default:
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    response.Titel = "Internal Server Error";
                    break;
            }

            httpContext.Response.StatusCode = response.StatusCode;
            await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);

            return true;
        }
    }
}
