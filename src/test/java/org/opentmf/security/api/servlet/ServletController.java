package org.opentmf.security.api.servlet;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import org.opentmf.security.exception.CarExistsException;
import org.opentmf.security.exception.CarNotFoundException;
import org.opentmf.security.model.Car;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Gokhan Demir
 */
@RestController
@ConditionalOnWebApplication(type = Type.SERVLET)
public class ServletController {

  private static final Map<String, Car> CARS = new LinkedHashMap<>();

  @PostMapping(path = "/car", consumes = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public void createCar(
      @RequestBody Car car,
      @RequestHeader(value = "Authorization") String authorization) {
    if (CARS.containsKey(car.getModel())) {
      throw new CarExistsException(car.getModel());
    }
    CARS.put(car.getModel(), car);
  }

  @GetMapping(path = "/car/{name}", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Car getCarByName(
      @PathVariable String name,
      @RequestHeader(value = "Authorization") String authorization) {
    if (!CARS.containsKey(name)) {
      throw new CarNotFoundException(name);
    }
    return CARS.get(name);
  }

  @PutMapping(path = "/car", consumes = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public void createOrUpdateCar(
      @RequestBody Car car,
      @RequestHeader(value = "Authorization") String authorization) {
    CARS.put(car.getModel(), car);
  }

  @GetMapping(path = "/car", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Collection<Car> getAllCars() {
    return CARS.values();
  }

  @DeleteMapping(path = "/car/{name}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteCarByName(
      @PathVariable String name,
      @RequestHeader(value = "Authorization") String authorization) {
    if (!CARS.containsKey(name)) {
      throw new CarNotFoundException(name);
    }
    CARS.remove(name);
  }

  @GetMapping(path = "/whitelist", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Collection<String> getWhitelist() {
    return List.of("/whitelist/**");
  }

  @GetMapping(path = "/protectedButNotConfigured", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Collection<String> getProtectedButNotConfigured(
      @RequestHeader(value = "Authorization") String authorization) {
    return List.of("/protectedButNotConfigured");
  }
}
