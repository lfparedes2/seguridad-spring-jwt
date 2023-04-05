package com.seguridad.dto;

import java.util.Date;

public class ErrorDetalles {

	private Date marcaDeTiempo;
	private String menasaje;
	private String detalles;

	public ErrorDetalles() {
		super();
	}

	public Date getMarcaDeTiempo() {
		return marcaDeTiempo;
	}

	public void setMarcaDeTiempo(Date marcaDeTiempo) {
		this.marcaDeTiempo = marcaDeTiempo;
	}

	public String getMenasaje() {
		return menasaje;
	}

	public void setMenasaje(String menasaje) {
		this.menasaje = menasaje;
	}

	public String getDetalles() {
		return detalles;
	}

	public void setDetalles(String detalles) {
		this.detalles = detalles;
	}

	public ErrorDetalles(Date marcaDeTiempo, String menasaje, String detalles) {
		super();
		this.marcaDeTiempo = marcaDeTiempo;
		this.menasaje = menasaje;
		this.detalles = detalles;
	}
	

}
