package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Hotel;
import com.zuehlke.securesoftwaredevelopment.domain.Reservation;
import com.zuehlke.securesoftwaredevelopment.domain.RoomType;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Controller
public class ReservationController {
    private static final Logger LOG = LoggerFactory.getLogger(ReservationController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(ReservationController.class);

    private ReservationRepository reservationRepository;
    private HotelRepository hotelRepository;
    private RoomRepository roomRepository;

    public ReservationController(ReservationRepository reservationRepository, HotelRepository hotelRepository, RoomRepository roomRepository) {
        this.reservationRepository = reservationRepository;
        this.hotelRepository = hotelRepository;
        this.roomRepository = roomRepository;
    }

    @GetMapping("/reservations/view")
    @PreAuthorize("hasAuthority('VIEW_RESERVATION')")
    public String view(Model model, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        Integer userId = user.getId();
        List<Reservation> userReservations = reservationRepository.forUser(userId);
        model.addAttribute("userReservations", userReservations);

        if (SecurityUtil.hasPermission("VIEW_PERSONS_LIST")) {
            List<Reservation> allReservations = reservationRepository.getAll();
            model.addAttribute("allReservations", allReservations);
        }

        return "reservations";
    }

    @GetMapping("/reservations/new/{id}")
    @PreAuthorize("hasAuthority('CREATE_RESERVATION')")
    public String showReservation(
            @PathVariable int id,
            Model model,
            @RequestParam(value = "cityInvalid", required = false) Boolean cityInvalid,
            @RequestParam(value = "countryMissing", required = false) Boolean countryMissing,
            @RequestParam(value = "cityExists", required = false) Boolean cityExists
    ) {
        Hotel hotel = hotelRepository.get(id);
        List<RoomType> roomTypes = roomRepository.getAllRoomTypes(id);

        model.addAttribute("id", id);
        model.addAttribute("hotel", hotel);
        model.addAttribute("roomTypes", roomTypes);

        return "reserve-hotel";
    }

    @PostMapping("/reservations/create")
    @PreAuthorize("hasAuthority('CREATE_RESERVATION')")
    public String createReservation(
            @RequestParam Integer hotelId,
            @RequestParam Integer roomTypeId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate,
            @RequestParam Integer roomsCount,
            @RequestParam Integer guestsCount,
            Authentication authentication
    ) {
        String redirectPage = "redirect:/reservations/new/" + hotelId;
        if (hotelId == null || hotelId <= 0) return redirectPage + "?createError=true";
        if (roomTypeId == null || roomTypeId <= 0) return redirectPage + "?createError=true";
        if (roomsCount == null || roomsCount <= 0) return redirectPage + "?createError=true";
        if (guestsCount == null || guestsCount <= 0) return redirectPage + "?createError=true";
        if (startDate == null || endDate == null || !endDate.isAfter(startDate)) {
            return redirectPage + "?dateError=true";
        }

        if (!hotelRepository.existsById(hotelId)) {
            return redirectPage + "?hotelError=true";
        }

        RoomType roomType = roomRepository.findByIdAndHotelId(roomTypeId, hotelId);
        if (roomType == null) {
            return redirectPage + "?roomTypeError=true";
        }

        long nights = ChronoUnit.DAYS.between(startDate, endDate);
        BigDecimal totalPrice = roomType.getPricePerNight()
                .multiply(BigDecimal.valueOf(nights))
                .multiply(BigDecimal.valueOf(roomsCount));

        int maxGuests = roomType.getCapacity() * roomsCount;
        if (guestsCount > maxGuests) {
            return redirectPage + "?createError=true";
        }

        User user = (User) authentication.getPrincipal();
        Integer userId = user.getId();

        Reservation r = new Reservation();
        r.setUserId(userId);
        r.setHotelId(hotelId);
        r.setRoomTypeId(roomTypeId);
        r.setStartDate(startDate);
        r.setEndDate(endDate);
        r.setRoomsCount(roomsCount);
        r.setGuestsCount(guestsCount);
        r.setTotalPrice(totalPrice);

        reservationRepository.create(r);
        auditLogger.audit("Created reservation: hotelId=" + hotelId + ", roomTypeId=" + roomTypeId
                + ", startDate=" + startDate + ", endDate=" + endDate + ", totalPrice=" + totalPrice);

        return redirectPage + "?created=true";
    }

    @PostMapping("/reservations/delete")
    @PreAuthorize("hasAuthority('VIEW_RESERVATION')")
    public String delete(@RequestParam Integer id) {
        auditLogger.audit("Deleted reservation: reservationId=" + id);
        reservationRepository.deleteById(id);
        return "redirect:/reservations/view";
    }
}
