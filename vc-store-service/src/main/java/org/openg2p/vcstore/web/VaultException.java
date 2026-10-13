package org.openg2p.vcstore.web;

import org.springframework.http.HttpStatus;

public class VaultException extends RuntimeException {
    private final HttpStatus status;
    private final String error;

    public VaultException(HttpStatus status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public HttpStatus status() {
        return status;
    }

    public String error() {
        return error;
    }
}
