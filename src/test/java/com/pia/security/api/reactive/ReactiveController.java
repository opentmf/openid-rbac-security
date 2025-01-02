package com.pia.security.api.reactive;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.pia.security.exception.CarExistsException;
import com.pia.security.exception.CarNotFoundException;
import com.pia.security.model.Car;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Gokhan Demir
 */
@RestController
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveController {

  private static final Map<String, Car> CARS = new LinkedHashMap<>();

  @PostMapping(path = "/car", consumes = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.CREATED)
  public Mono<Void> createCar(
      @RequestBody Car car,
      @RequestHeader(value = "Authorization") String authorization) {
    if (CARS.containsKey(car.getModel())) {
      return Mono.error(new CarExistsException(car.getModel()));
    }
    CARS.put(car.getModel(), car);
    return Mono.empty();
  }

  @GetMapping(path = "/car/{name}", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Mono<Car> getCarByName(
      @PathVariable String name,
      @RequestHeader(value = "Authorization") String authorization) {
    if (!CARS.containsKey(name)) {
      return Mono.error(new CarNotFoundException(name));
    }
    return Mono.just(CARS.get(name));
  }

  @PutMapping(path = "/car", consumes = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public Mono<Void> createOrUpdateCar(
      @RequestBody Car car,
      @RequestHeader(value = "Authorization") String authorization) {
    CARS.put(car.getModel(), car);
    return Mono.empty();
  }

  @GetMapping(path = "/car", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Flux<Car> getAllCars() {
    return Flux.fromIterable(CARS.values());
  }

  @DeleteMapping(path = "/car/{name}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public Mono<Void> deleteCar(
      @PathVariable String name,
      @RequestHeader(value = "Authorization") String authorization) {
    if (!CARS.containsKey(name)) {
      return Mono.error(new CarNotFoundException(name));
    }
    CARS.remove(name);
    return Mono.empty();
  }

  @GetMapping(path = "/whitelist", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Flux<String> getWhitelist() {
    return Flux.fromIterable(List.of("/whitelist/**"));
  }

  @GetMapping(path = "/protectedButNotConfigured", produces = APPLICATION_JSON_VALUE)
  @ResponseStatus(HttpStatus.OK)
  public @ResponseBody Flux<String> getProtectedButNotConfigured(
      @RequestHeader(value = "Authorization") String authorization) {
    return Flux.fromIterable(List.of("/protectedButNotConfigured"));
  }
}
