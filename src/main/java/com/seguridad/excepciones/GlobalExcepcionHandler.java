package com.seguridad.excepciones;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.seguridad.dto.ErrorDetalles;



@ControllerAdvice
public class GlobalExcepcionHandler extends ResponseEntityExceptionHandler{
	
	@ExceptionHandler(ResourceNotFoundExcepcion.class)
	public ResponseEntity<ErrorDetalles> manejarResourceNotFounExcepcion(ResourceNotFoundExcepcion excepcion, WebRequest webRequest){
		ErrorDetalles errorDetalles = new ErrorDetalles(new Date(), excepcion.getMessage(), webRequest.getDescription(false));
		return new ResponseEntity<>(errorDetalles,HttpStatus.NOT_FOUND);
	}
	
//	@ExceptionHandler(BlogAppExcepcion.class)
//	public ResponseEntity<ErrorDetalles> manejarBloAppExcepcion(BlogAppExcepcion excepcion, WebRequest webRequest){
//		ErrorDetalles errorDetalles = new ErrorDetalles(new Date(), excepcion.getMessage(), webRequest.getDescription(false));
//		return new ResponseEntity<>(errorDetalles,HttpStatus.BAD_REQUEST);
//	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorDetalles> manejarGlobalExcepcion(Exception excepcion, WebRequest webRequest){
		ErrorDetalles errorDetalles = new ErrorDetalles(new Date(), excepcion.getMessage(), webRequest.getDescription(false));
		return new ResponseEntity<>(errorDetalles,HttpStatus.INTERNAL_SERVER_ERROR);
	}
	
	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
		Map<String, String> errores = new HashMap<>();
		ex.getBindingResult().getAllErrors().forEach((error) -> {
			String nombreCampo =((FieldError)error).getField();
			String mensaje = error.getDefaultMessage();
			errores.put(nombreCampo, mensaje);
		});
		return  new ResponseEntity<>(errores, HttpStatus.BAD_REQUEST);
	}

}
