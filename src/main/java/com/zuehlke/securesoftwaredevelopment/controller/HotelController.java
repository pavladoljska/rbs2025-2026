package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.domain.*;
import com.zuehlke.securesoftwaredevelopment.repository.CityRepository;
import com.zuehlke.securesoftwaredevelopment.repository.HotelRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RatingRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RoomRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

@Controller
public class HotelController {
    private static final Logger LOG = LoggerFactory.getLogger(HotelController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(HotelController.class);
    private final HotelRepository hotelRepository;
    private final RoomRepository roomRepository;
    private final CityRepository cityRepository;
    private final RatingRepository ratingRepository;

    public HotelController(RoomRepository roomRepository, CityRepository cityRepository, HotelRepository hotelRepository, RatingRepository ratingRepository) {
        this.roomRepository = roomRepository;
        this.cityRepository = cityRepository;
        this.hotelRepository = hotelRepository;
        this.ratingRepository = ratingRepository;
    }

    @GetMapping("/")
    @PreAuthorize("hasAuthority('VIEW_HOTEL_LIST')")
    public String showSearch(Model model) {
        model.addAttribute("hotels", hotelRepository.getAll());
        return "hotels";
    }

    @GetMapping("/hotels")
    @PreAuthorize("hasAuthority('VIEW_HOTEL_LIST') or hasAuthority('VIEW_HOTEL')")
    public String showHotels(@RequestParam(name = "id", required = false) String id, Model model, Authentication authentication) {
        if (id == null) {
            model.addAttribute("hotels", hotelRepository.getAll());
            return "hotels";
        }
        User user = (User) authentication.getPrincipal();

        List<Rating> ratings = ratingRepository.getAll(id);
        Optional<Rating> userRating = ratings.stream().filter(rating -> rating.getUserId() == user.getId()).findFirst();
        userRating.ifPresent(rating -> model.addAttribute("userRating", rating.getRating()));
        if (!ratings.isEmpty()) {
            Integer sumRating = ratings.stream().map(rating -> rating.getRating()).reduce(0, (total, rating) -> total + rating);
            Double avgRating = (double) sumRating / ratings.size();
            model.addAttribute("averageRating", avgRating);
        }

        model.addAttribute("hotel", hotelRepository.get(Integer.valueOf(id)));

        return "hotel";
    }

    @GetMapping("/hotels/new-hotel")
    @PreAuthorize("hasAuthority('CREATE_HOTEL')")
    public String newHotel(
            Model model,
            @RequestParam(value = "hotelInvalid", required = false) Boolean hotelInvalid,
            @RequestParam(value = "hotelExists", required = false) Boolean hotelExists,
            @RequestParam(value = "cityMissing", required = false) Boolean cityMissing
    ) {
        List<City> cityList = cityRepository.getAll();
        List<Hotel> hotelList = hotelRepository.getAll();
        model.addAttribute("cities", cityList);
        model.addAttribute("hotels", hotelList);

        model.addAttribute("hotelInvalid", Boolean.TRUE.equals(hotelInvalid));
        model.addAttribute("hotelExists", Boolean.TRUE.equals(hotelExists));
        model.addAttribute("cityMissing", Boolean.TRUE.equals(cityMissing));
        return "new-hotel";
    }

    @PostMapping("/hotels/create")
    @PreAuthorize("hasAuthority('CREATE_HOTEL')")
    public String createHotel(
      @RequestParam Integer cityId,
      @RequestParam String name,
      @RequestParam String description,
      @RequestParam String address
    ) {
        if (cityId == null || cityId <= 0) {
            return "redirect:/hotels/new-hotel?cityMissing=true";
        }

        City city = cityRepository.findById(cityId);
        if (city == null) {
            return "redirect:/hotels/new-hotel?cityMissing=true";
        }

        if (name.length() < 2 || name.length() > 200) {
            return "redirect:/hotels/new-hotel?hotelInvalid=true";
        }

        if (description.length() < 10 || description.length() > 511) {
            return "redirect:/hotels/new-hotel?hotelInvalid=true";
        }

        if (address != null && address.length() > 255) {
            return "redirect:/hotels/new-hotel?hotelInvalid=true";
        }

        Hotel hotel = new Hotel(cityId, name, description, address);
        hotelRepository.create(hotel);
        LOG.info("Hotel created: name='{}', cityId={}", name, cityId);

        return "redirect:/hotels/new-hotel";
    }

    @GetMapping("/api/hotels/{hotelId}/room-types")
    @PreAuthorize("hasAuthority('VIEW_HOTEL')")
    public ResponseEntity<List<RoomType>> getRoomTypesForHotel(@PathVariable Integer hotelId) {
        List<RoomType> result = roomRepository.getAllRoomTypes(hotelId);
        return ResponseEntity.ok(result);
    }

    @GetMapping(value = "/api/hotels/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_HOTEL_LIST')")
    public List<Hotel> search(@RequestParam("query") String query) throws SQLException {
        LOG.debug("Hotel search performed: query='{}'", query);
        return hotelRepository.search(query);
    }
}
