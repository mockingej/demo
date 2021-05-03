package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping(value = "/management/api/v1/students/")
public class StudentManagementController {

    private final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Adolf Bean"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerStudent(@RequestBody Student student) {
        System.out.println("---------------------");
        System.out.println("registerStudent");
        System.out.println(student);
        System.out.println("---------------------");
    }

    @DeleteMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("id") Integer id) {
        System.out.println("---------------------");
        System.out.println("deleteStudent");
        System.out.println(id);
        System.out.println("---------------------");
    }

    @PutMapping(path = "{id}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("id") Integer id, @RequestBody Student student) {
        System.out.println("---------------------");
        System.out.println("updateStudent");
        System.out.printf("%s %s%n", id, student);
        System.out.println("---------------------");
    }

}
