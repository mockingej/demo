package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping(value = "/api/v1/students/")
public class StudentController {

    List<Student> STUDENTS = Arrays.asList(
      new Student(1, "James Bond"),
      new Student(2, "Adolf Bean"),
      new Student(3, "Anna Smith")
    );

    @GetMapping(path = "{id}")
    public Student getStudent(@PathVariable("id") Integer id) {
        return STUDENTS
                .stream()
                .filter(student -> student.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + id + " does not exists"));
    }


}
