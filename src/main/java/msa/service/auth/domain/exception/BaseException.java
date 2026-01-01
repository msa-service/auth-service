package msa.service.auth.domain.exception;


import org.springframework.http.HttpStatus;

public abstract class BaseException extends RuntimeException {
    public abstract HttpStatus getStatus();
    public abstract String getErrorCode();

    public BaseException(String msg) {
        super(msg);
    }
}
