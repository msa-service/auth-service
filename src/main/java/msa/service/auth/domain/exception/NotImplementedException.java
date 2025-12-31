package msa.service.auth.domain.exception;

import org.springframework.http.HttpStatus;

public class NotImplementedException extends BaseException{
    public NotImplementedException(String msg) {
        super(msg);
    }

    @Override
    public HttpStatus getStatus() {
        return HttpStatus.NOT_IMPLEMENTED;
    }

    @Override
    public String getErrorCode() {
        return "NOT IMPLEMENTED";
    }
}
