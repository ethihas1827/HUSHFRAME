/**
 * @file api.h
 * @brief JSON API routing and endpoint handlers for bmp-stego web service.
 */

#ifndef STEGO_API_H
#define STEGO_API_H

#include "http.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Dispatch incoming API request to the appropriate endpoint handler.
 *
 * @param req Incoming HTTP request
 * @param res Outgoing HTTP response
 */
void api_handle_request(const HttpRequest *req, HttpResponse *res);

#ifdef __cplusplus
}
#endif

#endif /* STEGO_API_H */
