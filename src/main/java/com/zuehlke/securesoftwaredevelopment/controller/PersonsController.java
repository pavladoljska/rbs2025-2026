package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.Entity;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonsController.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) {
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + id));
        model.addAttribute("username", userRepository.findUsername(id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + user.getId()));
        model.addAttribute("username", userRepository.findUsername(user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id) {
        User currentUser = SecurityUtil.getCurrentUser();
        if (!SecurityUtil.hasPermission("VIEW_PERSON") && currentUser.getId() != id) {
            LOG.warn("User id={} attempted to delete person id={} without permission", currentUser.getId(), id);
            throw new AccessDeniedException("You can only delete your own profile.");
        }
        Person personBefore = personRepository.get("" + id);
        personRepository.delete(id);
        userRepository.delete(id);
        auditLogger.audit("Deleted person: id=" + id + ", firstName='" + personBefore.getFirstName() + "', lastName='" + personBefore.getLastName() + "'");

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, String username, HttpSession session, @RequestParam("csrfToken") String csrfToken) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if (!csrf.equals(csrfToken)) {
            LOG.warn("CSRF token mismatch for user id={} when updating person id={}", SecurityUtil.getCurrentUser() != null ? SecurityUtil.getCurrentUser().getId() : "unknown", person.getId());
            return "redirect:/error";
        }
        User currentUser = SecurityUtil.getCurrentUser();
        if (!SecurityUtil.hasPermission("VIEW_PERSON") && currentUser.getId() != Integer.parseInt(person.getId())) {
            LOG.warn("User id={} attempted to update person id={} without permission", currentUser.getId(), person.getId());
            throw new AccessDeniedException("You can only update your own profile.");
        }
        Person personBefore = personRepository.get(person.getId());
        String oldUsername = userRepository.findUsername(Integer.parseInt(person.getId()));
        personRepository.update(person);
        userRepository.updateUsername(Integer.parseInt(person.getId()), username);
        auditLogger.auditChange(new Entity("Person", person.getId(),
                "firstName='" + personBefore.getFirstName() + "', lastName='" + personBefore.getLastName() + "', email='" + personBefore.getEmail() + "', username='" + oldUsername + "'",
                "firstName='" + person.getFirstName() + "', lastName='" + person.getLastName() + "', email='" + person.getEmail() + "', username='" + username + "'"));
        if(SecurityUtil.hasPermission("VIEW_PERSON")) {
            return "redirect:/persons/" + person.getId();
        }
        return "redirect:/myprofile";
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        LOG.debug("Person search performed: searchTerm='{}'", searchTerm);
        return personRepository.search(searchTerm);
    }
}
