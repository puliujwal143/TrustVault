/**
 * Private document storage engine abstractions and filesystem implementations.
 *
 * <p>Enforces secure, private storage of document files outside static web directories,
 * utilizing non-predictable UUID storage identifiers to prevent path traversal and unauthorized
 * direct static URL access.
 */
package com.trustvault.storage;
