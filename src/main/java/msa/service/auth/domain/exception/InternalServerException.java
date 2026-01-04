package msa.service.auth.domain.exception;

import org.springframework.http.HttpStatus;

public class InternalServerException extends BaseException{
    public InternalServerException(String msg) {
        super(msg);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    @Override
    public String getErrorCode() {
        return "INTERNAL_SERVER_ERROR";
    }
}
